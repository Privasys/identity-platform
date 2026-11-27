// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The stored session and the page that watches it: the refresh grant, its
 * lock and timers, the report of every change to the page, and the
 * messages about the session (check, renew, clear, mint).
 */

import { SESSIONS_STORAGE_KEY, sessionKeyId, type SessionKey } from '../session';
import type { AuthSession } from '../types';
import { methodOf, pageIsClients, sessions, sessionForPage } from './page-scope';
import type { MessageContext } from './router';
import { tokenExpMs, tokenAudienceIs, isTokenExpired, tokenSid } from './tokens';

// ── Renewal (OIDC refresh_token) ─────────────────────────────────────────
//
// Several privasys.id documents can hold the same session at once: the
// persistent frame of each tab, and a gate frame during a sign-in. The
// identity provider rotates refresh tokens with strict single use (the old
// token is deleted before the new one is issued), so exactly one document
// may run a refresh grant for a session at a time. Every grant goes through
// refreshGrant, which holds a Web Locks API lock (origin-scoped across
// documents and tabs) for it.
//
// Renewal is scheduled from the access token's `exp` claim, retries
// transient failures with backoff, and never removes the session unless the
// refresh-token chain is provably dead.

/** Renew when the token has less than this long to live. */
export const RENEW_MARGIN_MS = 90_000;
/** Random spread so N documents don't fire at the same instant. */
export const RENEW_JITTER_MS = 15_000;
/** Backoff schedule for transient renewal failures (network, IdP 5xx). */
export const RENEW_RETRY_MS = [5_000, 30_000, 120_000];
/** Backstop cadence; no-ops unless the token is inside the margin. */
export const RENEW_HEARTBEAT_MS = 60_000;

// Timers and retries per session key. A timer outlives the message that
// armed it, so it holds its key.
export const renewalTimers = new Map<string, ReturnType<typeof setTimeout>>();
export const renewalRetryCount = new Map<string, number>();

/**
 * A session the page of this document watches: its key, the page's origin
 * to report to, and the token last reported (null for no session).
 */
export interface Watch {
    key: SessionKey;
    parentOrigin: string;
    token: string | null;
}

/** The sessions this document's page watches, by session key id. */
export const watches = new Map<string, Watch>();

/** Called when a watched session changes: a new token, removed, appeared. */
const changeListeners = new Set<(key: SessionKey, session: AuthSession | undefined) => void>();

export function onWatchedSessionChange(cb: (key: SessionKey, session: AuthSession | undefined) => void): void {
    changeListeners.add(cb);
}

/** What the page is told about a session: never its refresh token. */
export function pageView(session: AuthSession | undefined): Record<string, unknown> | null {
    if (!session) return null;
    return {
        token: session.token,
        method: methodOf(session),
        requestedAttributes: session.requestedAttributes ?? [],
        scope: session.scope ?? '',
    };
}

/** Watch a session for the page, from what the page was just told. */
export function watch(key: SessionKey, parentOrigin: string, told: AuthSession | undefined): void {
    watches.set(sessionKeyId(key), { key, parentOrigin, token: told?.token ?? null });
}

/**
 * Report every watched session whose token changed since the page was last
 * told: renewed, signed in, signed out or expired, by this document or by
 * another tab. A page the client does not accept is told nothing.
 */
export async function reportChanges(): Promise<void> {
    for (const w of watches.values()) {
        const current = sessions.get(w.key);
        const token = current?.token ?? null;
        if (token === w.token) continue;
        w.token = token;
        if (current?.refreshToken) scheduleRenewal(w.key, current, w.parentOrigin);
        else cancelRenewal(w.key);
        for (const cb of changeListeners) {
            try { cb(w.key, current); } catch { /* isolate */ }
        }
        if (current && !(await pageIsClients(w.key.clientId, w.parentOrigin))) continue;
        try {
            window.parent.postMessage(
                { type: 'privasys:session-changed', clientId: w.key.clientId, session: pageView(current) },
                w.parentOrigin,
            );
        } catch { /* parent gone */ }
    }
}

export function cancelRenewal(key: SessionKey): void {
    const id = sessionKeyId(key);
    const timer = renewalTimers.get(id);
    if (timer) {
        clearTimeout(timer);
        renewalTimers.delete(id);
    }
    renewalRetryCount.delete(id);
}

/**
 * Serialise a refresh-token grant across all privasys.id documents (frames
 * and tabs). Runs unlocked when the Web Locks API is unavailable.
 */
export async function withRefreshLock<T>(key: SessionKey, fn: () => Promise<T>): Promise<T> {
    const locks = (navigator as Navigator & { locks?: LockManager }).locks;
    if (locks?.request) {
        return locks.request(`privasys-refresh:${sessionKeyId(key)}`, fn) as Promise<T>;
    }
    return fn();
}

/** True when the token should be renewed now (inside the renewal margin). */
export function needsRenewal(token: string): boolean {
    return isTokenExpired(token, RENEW_MARGIN_MS);
}

export function scheduleRenewal(key: SessionKey, session: AuthSession, parentOrigin: string): void {
    const id = sessionKeyId(key);
    cancelRenewal(key);
    if (!session.refreshToken) return;

    // Scheduled from the token's own exp; an unreadable exp renews after
    // 13 minutes.
    const exp = tokenExpMs(session.token);
    const base = exp === null ? 13 * 60 * 1000 : exp - Date.now() - RENEW_MARGIN_MS;
    const jitter = Math.floor(Math.random() * RENEW_JITTER_MS);
    const delay = Math.max(1_000, base + jitter);

    renewalTimers.set(id, setTimeout(() => {
        renewalTimers.delete(id);
        void renewIfNeeded(key, parentOrigin);
    }, delay));
}

export function scheduleRenewalRetry(key: SessionKey, parentOrigin: string): void {
    const id = sessionKeyId(key);
    const attempt = renewalRetryCount.get(id) ?? 0;
    renewalRetryCount.set(id, attempt + 1);
    const delay = RENEW_RETRY_MS[Math.min(attempt, RENEW_RETRY_MS.length - 1)];
    const prev = renewalTimers.get(id);
    if (prev) clearTimeout(prev);
    renewalTimers.set(id, setTimeout(() => {
        renewalTimers.delete(id);
        void renewIfNeeded(key, parentOrigin);
    }, delay));
}

/**
 * What one refresh grant came to.
 *  - granted: the identity provider answered; the rotated refresh token (and,
 *    for a renewal, the new access token) is stored.
 *  - current: the session is not due, or another document already renewed it.
 *  - adopted: the token was spent, but storage holds a newer one that another
 *    document stored meanwhile; that session stands.
 *  - dead: the chain is gone (revoked, expired); the session was removed.
 *  - failed: network or server trouble; the session is kept as it was.
 *  - none: there is no session with a refresh token.
 */
export type GrantResult =
    | { kind: 'granted'; session: AuthSession; accessToken: string; expiresIn: number }
    | { kind: 'current' | 'adopted'; session: AuthSession }
    | { kind: 'failed'; session: AuthSession; error: string }
    | { kind: 'dead' | 'none' };

/**
 * Run one refresh_token grant for a session: the only place this frame spends a
 * refresh token. Under the cross-document lock it re-reads the session
 * (another document may have renewed it while this one waited), tells the page
 * a grant is in flight, and stores what comes back before the page may tear
 * the frame down.
 *
 * Without `scope` it renews the session: the new access token replaces the
 * stored one. With `scope` it mints a token for another audience: only the
 * rotated refresh token is stored, since the minted access token is bound to
 * that audience. `due`, when given, skips the grant for a session that does
 * not need it. A dead chain is removed, which the watching page is told.
 */
export async function refreshGrant(
    key: SessionKey,
    opts: { parentOrigin: string; scope?: string; due?: (s: AuthSession) => boolean },
): Promise<GrantResult> {
    return withRefreshLock(key, async (): Promise<GrantResult> => {
        const session = sessions.get(key);
        if (!session?.refreshToken) return { kind: 'none' };
        if (opts.due && !opts.due(session)) return { kind: 'current', session };
        const usedRefreshToken = session.refreshToken;

        // The identity provider deletes the old refresh token before it issues
        // the new one, so a frame removed between the request and the stored
        // response kills the chain. The page defers teardown while this is set.
        const signal = (phase: 'start' | 'end') => {
            if (!opts.parentOrigin) return;
            try {
                window.parent.postMessage({ type: 'privasys:renewal', phase }, opts.parentOrigin);
            } catch { /* parent gone */ }
        };
        signal('start');
        let resp: Response;
        try {
            resp = await fetch(`${globalThis.location.origin}/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    grant_type: 'refresh_token',
                    refresh_token: usedRefreshToken,
                    client_id: key.clientId,
                    ...(opts.scope ? { scope: opts.scope } : {}),
                }),
            });
        } catch (err) {
            signal('end');
            return { kind: 'failed', session, error: err instanceof Error ? err.message : 'network error' };
        }
        const body = await resp.json().catch(() => null) as Record<string, unknown> | null;
        if (resp.ok && typeof body?.access_token === 'string' && typeof body.refresh_token === 'string' && body.refresh_token) {
            const updated: AuthSession = opts.scope
                ? { ...session, refreshToken: body.refresh_token }
                : { ...session, token: body.access_token, refreshToken: body.refresh_token, authenticatedAt: Date.now() };
            sessions.store(key, updated);
            signal('end');
            const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : 0;
            return { kind: 'granted', session: updated, accessToken: body.access_token, expiresIn };
        }
        signal('end');

        const errCode = typeof body?.error === 'string' ? body.error : '';
        if (resp.status === 400 && errCode === 'invalid_grant') {
            const stored = sessions.get(key);
            if (stored?.refreshToken && stored.refreshToken !== usedRefreshToken) {
                return { kind: 'adopted', session: stored };
            }
            console.warn('[frame-host] refresh-token chain dead, expiring session:', body);
            cancelRenewal(key);
            sessions.remove(key);
            return { kind: 'dead' };
        }
        const error = typeof body?.error_description === 'string' ? body.error_description
            : errCode || `refresh failed: ${resp.status}`;
        return { kind: 'failed', session, error };
    });
}

/**
 * Renew a session and keep its renewal going: re-arm the timer from the
 * fresh token and retry a failure with backoff. The watching page hears of
 * the new token through {@link reportChanges}.
 *
 * Returns the freshest session (renewed or not), or undefined when the chain
 * is dead and the session has been removed.
 */
export async function renewSession(
    key: SessionKey,
    parentOrigin: string,
    due?: (s: AuthSession) => boolean,
): Promise<AuthSession | undefined> {
    const r = await refreshGrant(key, { parentOrigin, due });
    switch (r.kind) {
        case 'none':
            return sessions.get(key);
        case 'dead':
            return undefined;
        case 'failed':
            console.warn('[frame-host] renewal failed, will retry:', r.error);
            scheduleRenewalRetry(key, parentOrigin);
            return r.session;
        default:
            renewalRetryCount.delete(sessionKeyId(key));
            scheduleRenewal(key, r.session, parentOrigin);
            return r.session;
    }
}

/**
 * Renew the session if (and only if) its token is inside the renewal margin.
 * A renewal another document just completed makes this a no-op that re-arms
 * the timer from the fresh expiry.
 */
export async function renewIfNeeded(key: SessionKey, parentOrigin: string): Promise<AuthSession | undefined> {
    const current = sessions.get(key);
    if (!current?.refreshToken) return current;
    if (!needsRenewal(current.token)) {
        if (!renewalTimers.has(sessionKeyId(key))) scheduleRenewal(key, current, parentOrigin);
        return current;
    }
    return renewSession(key, parentOrigin, (s) => needsRenewal(s.token));
}

// Renewals a page asked for now, per session: calls made while one waits or
// runs share it, and a session renews this way at most once per
// RENEW_NOW_MIN_MS.
export const RENEW_NOW_MIN_MS = 10_000;
export const renewalsNow = new Map<string, Promise<AuthSession | undefined>>();
export const lastRenewNow = new Map<string, number>();

/**
 * Renew the session now, whatever its token's expiry: what the person may do
 * has changed (a role was granted, an account switched), and a renewal reads
 * it afresh. Within RENEW_NOW_MIN_MS of the last one, the renewal runs when
 * that time is up, so a page asking in a loop makes one grant per interval.
 *
 * Resolves with the renewed session, the unchanged one when the renewal
 * could not run (it is retried as usual), or undefined when the chain is dead.
 */
export function renewNow(key: SessionKey, parentOrigin: string): Promise<AuthSession | undefined> {
    const id = sessionKeyId(key);
    const pending = renewalsNow.get(id);
    if (pending) return pending;
    const wait = Math.max(0, (lastRenewNow.get(id) ?? 0) + RENEW_NOW_MIN_MS - Date.now());
    const run = new Promise<void>((r) => setTimeout(r, wait))
        .then(() => {
            // What the person may do changed: tokens minted for audiences
            // under the old roles are not reused.
            for (const k of minted.keys()) if (k.startsWith(`${id}|`)) minted.delete(k);
            lastRenewNow.set(id, Date.now());
            return renewSession(key, parentOrigin);
        })
        .finally(() => renewalsNow.delete(id));
    renewalsNow.set(id, run);
    return run;
}

/**
 * Keep this document's sessions current: report changes made here and by
 * other documents, and renew any session a late timer missed.
 */
export function startRenewalWatch(): void {
    // Changes this document makes.
    sessions.subscribe(() => { void reportChanges(); });
    // Changes other documents make (`storage` fires in every same-origin
    // document except the writer).
    window.addEventListener('storage', (ev) => {
        if (ev.key === SESSIONS_STORAGE_KEY || ev.key === null) void reportChanges();
    });

    // Backstop heartbeat: one-shot timers can fire arbitrarily late in
    // throttled or suspended documents. The lock and the in-lock re-read make
    // overlapping heartbeats across documents harmless.
    setInterval(() => {
        for (const { key, parentOrigin } of watches.values()) {
            const current = sessions.get(key);
            if (current?.refreshToken && needsRenewal(current.token)) void renewIfNeeded(key, parentOrigin);
        }
    }, RENEW_HEARTBEAT_MS);
}

// The page asks for its session, and is told of every change to it from
// then on, signed in or not.
export async function onCheckSession({ e, data, key }: MessageContext): Promise<void> {
    let session = await sessionForPage(key, e.origin);

    // A token inside the renewal margin is renewed before the page gets it.
    // A dead chain comes back as undefined.
    if (key && session?.refreshToken && needsRenewal(session.token)) {
        session = await renewIfNeeded(key, e.origin);
    }
    if (key) {
        watch(key, e.origin, session);
        if (session?.refreshToken && !renewalTimers.has(sessionKeyId(key))) {
            scheduleRenewal(key, session, e.origin);
        }
    }
    window.parent.postMessage({ type: 'privasys:session', id: data.id, session: pageView(session) }, e.origin);
}

// Renew now, for a page that knows what the person may do has changed.
// Only the page this frame serves may ask, for its own session.
export async function onRenewSession({ e, data, key }: MessageContext): Promise<void> {
    const id = data.id;
    const reply = (payload: Record<string, unknown>) =>
        window.parent.postMessage({ type: 'privasys:renew-session:response', id, ...payload }, e.origin);
    const session = await sessionForPage(key, e.origin);
    if (!key || !session?.refreshToken) {
        reply({ error: 'no session to renew' });
        return;
    }
    const before = session.token;
    const after = await renewNow(key, e.origin);
    if (!after) reply({ error: 'session expired' });
    else if (after.token === before) reply({ error: 'renewal failed; it will be retried' });
    else reply({ session: pageView(after) });
}

export async function onClearSession({ e, data, key }: MessageContext): Promise<void> {
    // Signing out ends the session in every tab of the site. The remembered
    // wallets stay: each is forgotten by itself, from the gate.
    if (key && await sessionForPage(key, e.origin)) {
        cancelRenewal(key);
        sessions.remove(key);
    }
    window.parent.postMessage({ type: 'privasys:session-cleared', id: data.id }, e.origin);
}

// Mint an access token for another audience without replacing the
// session's own: a refresh_token grant with an explicit `scope` (RFC 6749
// section 6, plus the audience extension), under the session's own
// granted scopes, since the identity provider refuses a broader one. The
// rotated refresh token keeps the original scope, so later renewals still
// mint the session's audience.
// Tokens minted for an audience, kept until shortly before they expire so a
// page asking for one per request (a direct channel) costs one grant per
// token lifetime. Each is bound to the sign-in (sid) it was minted from.
const MINT_REUSE_MARGIN_MS = 60_000;
const minted = new Map<string, { sid: string; token: string; expiresIn: number; expMs: number }>();
const minting = new Map<string, Promise<Record<string, unknown>>>();

export async function onGetTokenForAudience({ e, data, key, pageScope }: MessageContext): Promise<void> {
    const id = data.id;
    const reply = (payload: Record<string, unknown>) =>
        window.parent.postMessage(
            { type: 'privasys:token-for-audience:response', id, ...payload },
            e.origin,
        );
    const session = await sessionForPage(key, e.origin);
    if (!key || !session?.refreshToken) {
        reply({ error: 'no refresh token in session' });
        return;
    }
    const audience = String(data.audience || '').trim();
    if (!audience) {
        reply({ error: 'audience required' });
        return;
    }
    // Another platform's audience is never minted for this page.
    if (!pageScope || (pageScope.platforms.includes(audience) && audience !== pageScope.platform)) {
        reply({ error: `audience ${audience} is not for a page on this platform` });
        return;
    }
    // The first token already made for this audience is still good: it is
    // the one carrying the profile, and a refresh would only replace it
    // with one that does not.
    if (session.token && tokenAudienceIs(session.token, audience) && !isTokenExpired(session.token)) {
        const exp = tokenExpMs(session.token);
        reply({ accessToken: session.token, expiresIn: exp === null ? 0 : Math.floor((exp - Date.now()) / 1000) });
        return;
    }
    const sid = tokenSid(session.token) ?? '';
    const cacheKey = `${sessionKeyId(key)}|${audience}`;
    const cached = minted.get(cacheKey);
    if (cached && cached.sid === sid && cached.expMs - MINT_REUSE_MARGIN_MS > Date.now()) {
        reply({ accessToken: cached.token, expiresIn: Math.floor((cached.expMs - Date.now()) / 1000) });
        return;
    }
    let pending = minting.get(cacheKey);
    if (!pending) {
        pending = mintFor(key, e.origin, `audience:${audience} ${session.scope}`).then((out) => {
            if (typeof out.accessToken === 'string') {
                const expMs = tokenExpMs(out.accessToken) ?? Date.now() + Number(out.expiresIn ?? 0) * 1000;
                minted.set(cacheKey, { sid, token: out.accessToken, expiresIn: Number(out.expiresIn ?? 0), expMs });
            }
            return out;
        }).finally(() => minting.delete(cacheKey));
        minting.set(cacheKey, pending);
    }
    reply(await pending);
}

async function mintFor(key: SessionKey, parentOrigin: string, scope: string): Promise<Record<string, unknown>> {
    let r = await refreshGrant(key, { parentOrigin, scope });
    // Another document rotated the token while this grant was in flight:
    // mint again from the one it stored.
    if (r.kind === 'adopted') r = await refreshGrant(key, { parentOrigin, scope });
    if (r.kind === 'granted') return { accessToken: r.accessToken, expiresIn: r.expiresIn };
    if (r.kind === 'dead') return { error: 'session expired' };
    if (r.kind === 'failed') return { error: r.error };
    return { error: 'no refresh token in session' };
}
