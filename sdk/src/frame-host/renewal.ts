// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * Session renewal: the refresh grant, its lock and timers, and the
 * messages about the stored session (check, renew, clear, mint).
 */

import { SESSIONS_STORAGE_KEY, sessionKeyId, type SessionKey } from '../session';
import type { AuthSession } from '../types';
import { sessions, sessionForPage } from './page-scope';
import type { MessageContext } from './router';
import { tokenExpMs, tokenAudienceIs, isTokenExpired } from './tokens';

// ── Session renewal (OIDC refresh_token) ────────────────────────────────
//
// Renewal coordination is client-side and cross-document. Several
// privasys.id iframes can be alive at once for the same session: the
// persistent renewal iframe, a sealed sign-in iframe kept mounted for
// session-relay, and one of each per additional tab. The IdP rotates
// refresh tokens with strict single-use semantics (the old token is
// deleted before the new one is issued), so exactly one document may run
// a refresh grant for a given session at a time. Every grant goes through
// refreshGrant, which holds a Web Locks API lock (origin-scoped across
// documents and tabs) for it.
//
// Renewal is scheduled from the access token's `exp` claim (not a flat
// delay), retries transient failures with backoff, and never removes
// the session unless the refresh-token chain is provably dead.

/** Renew when the token has less than this long to live. */
export const RENEW_MARGIN_MS = 90_000;
/** Random spread so N documents don't fire at the same instant. */
export const RENEW_JITTER_MS = 15_000;
/** Backoff schedule for transient renewal failures (network, IdP 5xx). */
export const RENEW_RETRY_MS = [5_000, 30_000, 120_000];
/** Backstop cadence; no-ops unless the token is inside the margin. */
export const RENEW_HEARTBEAT_MS = 60_000;

// Everything this document renews is kept per session key, so two clients
// sharing an rpId keep their own timers, retries and notifications. A timer
// outlives the message that armed it, so it holds its key.
export const renewalTimers = new Map<string, ReturnType<typeof setTimeout>>();
export const renewalRetryCount = new Map<string, number>();
/** Sessions this document renews, with the parent origin to notify. */
export const renewalParents = new Map<string, { key: SessionKey; parentOrigin: string }>();
/** Last access token seen per session; dedupes storage-event notifications. */
export const lastSeenTokens = new Map<string, string>();

export function cancelRenewal(key: SessionKey): void {
    const id = sessionKeyId(key);
    const timer = renewalTimers.get(id);
    if (timer) {
        clearTimeout(timer);
        renewalTimers.delete(id);
    }
    renewalRetryCount.delete(id);
    renewalParents.delete(id);
}

/**
 * Serialise a refresh-token-grant user across all privasys.id documents
 * (iframes and tabs). Falls back to running unlocked when the Web Locks
 * API is unavailable — best effort, matching pre-lock behaviour.
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

    renewalParents.set(id, { key, parentOrigin });
    lastSeenTokens.set(id, session.token);

    // Schedule from the token's actual exp; a flat delay drifts apart
    // from the token lifetime whenever the iframe is (re)created after
    // sign-in. An unreadable exp renews after 13 minutes.
    const exp = tokenExpMs(session.token);
    const base = exp === null ? 13 * 60 * 1000 : exp - Date.now() - RENEW_MARGIN_MS;
    const jitter = Math.floor(Math.random() * RENEW_JITTER_MS);
    const delay = Math.max(1_000, base + jitter);

    const timer = setTimeout(() => {
        renewalTimers.delete(id);
        void renewIfNeeded(key, parentOrigin);
    }, delay);

    renewalTimers.set(id, timer);
}

export function scheduleRenewalRetry(key: SessionKey, parentOrigin: string): void {
    const id = sessionKeyId(key);
    const attempt = renewalRetryCount.get(id) ?? 0;
    renewalRetryCount.set(id, attempt + 1);
    const delay = RENEW_RETRY_MS[Math.min(attempt, RENEW_RETRY_MS.length - 1)];
    const prev = renewalTimers.get(id);
    if (prev) clearTimeout(prev);
    const timer = setTimeout(() => {
        renewalTimers.delete(id);
        void renewIfNeeded(key, parentOrigin);
    }, delay);
    renewalTimers.set(id, timer);
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
 * not need it. A dead chain is removed, and the page told when `notify` is set.
 */
export async function refreshGrant(
    key: SessionKey,
    opts: { parentOrigin: string; notify: boolean; scope?: string; due?: (s: AuthSession) => boolean },
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
                window.parent.postMessage({ type: 'privasys:renewal', rpId: session.rpId, phase }, opts.parentOrigin);
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
            if (opts.notify && opts.parentOrigin) {
                window.parent.postMessage({ type: 'privasys:session-expired', rpId: session.rpId }, opts.parentOrigin);
            }
            return { kind: 'dead' };
        }
        const error = typeof body?.error_description === 'string' ? body.error_description
            : errCode || `refresh failed: ${resp.status}`;
        return { kind: 'failed', session, error };
    });
}

/**
 * Renew a session and keep its renewal going: re-arm the timer from
 * the fresh token, retry a failure with backoff, and tell the page about the
 * new token when `notify` is set (a check-session that renews inline answers
 * with the session itself instead).
 *
 * Returns the freshest session (renewed or not), or undefined when the chain
 * is dead and the session has been removed.
 */
export async function renewSession(
    key: SessionKey,
    parentOrigin: string,
    notify: boolean,
    due?: (s: AuthSession) => boolean,
): Promise<AuthSession | undefined> {
    const r = await refreshGrant(key, { parentOrigin, notify, due });
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
            if (r.kind === 'granted' && notify) {
                window.parent.postMessage(
                    { type: 'privasys:session-renewed', rpId: r.session.rpId, accessToken: r.session.token },
                    parentOrigin,
                );
            }
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
export async function renewIfNeeded(
    key: SessionKey,
    parentOrigin: string,
    notify = true,
): Promise<AuthSession | undefined> {
    const current = sessions.get(key);
    if (!current?.refreshToken) return current;
    if (!needsRenewal(current.token)) {
        if (!renewalTimers.has(sessionKeyId(key))) scheduleRenewal(key, current, parentOrigin);
        return current;
    }
    return renewSession(key, parentOrigin, notify, (s) => needsRenewal(s.token));
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
            lastRenewNow.set(id, Date.now());
            return renewSession(key, parentOrigin, true);
        })
        .finally(() => renewalsNow.delete(id));
    renewalsNow.set(id, run);
    return run;
}

/**
 * Keep this document's renewals going: follow renewals other documents
 * make, and renew any session a late timer missed.
 */
export function startRenewalWatch(): void {
    // Cross-document propagation: when another iframe/tab renews a session
    // we track, re-arm our timer from the fresh exp and forward the new
    // access token to our parent so its in-memory copy doesn't go stale.
    // (`storage` fires in every same-origin document except the writer.)
    window.addEventListener('storage', (ev) => {
        if (ev.key !== SESSIONS_STORAGE_KEY) return;
        for (const [id, { key, parentOrigin }] of renewalParents) {
            const current = sessions.get(key);
            if (!current?.refreshToken) continue;
            if (lastSeenTokens.get(id) === current.token) continue;
            lastSeenTokens.set(id, current.token);
            scheduleRenewal(key, current, parentOrigin);
            window.parent.postMessage(
                {
                    type: 'privasys:session-renewed',
                    rpId: key.rpId,
                    accessToken: current.token,
                },
                parentOrigin,
            );
        }
    });

    // Backstop heartbeat: one-shot timers can fire arbitrarily late in
    // throttled/suspended documents. This interval (clamped to ≥1/min by
    // the browser anyway) renews any tracked session that slipped inside
    // the margin; the lock + in-lock re-read make overlapping heartbeats
    // across documents harmless no-ops.
    setInterval(() => {
        for (const { key, parentOrigin } of renewalParents.values()) {
            const current = sessions.get(key);
            if (!current?.refreshToken) continue;
            if (needsRenewal(current.token)) void renewIfNeeded(key, parentOrigin);
        }
    }, RENEW_HEARTBEAT_MS);

}

export async function onCheckSession({ e, key }: MessageContext): Promise<void> {
    let session = await sessionForPage(key, e.origin);

    // If the access token is inside the renewal margin and we have a
    // refresh token, renew inline (under the cross-document lock)
    // before returning so the parent gets a fresh token. A dead
    // chain comes back as undefined → parent triggers sign-in.
    if (key && session?.refreshToken && needsRenewal(session.token)) {
        session = await renewIfNeeded(key, e.origin, false);
    }

    // Ensure renewal is running for active sessions
    if (key && session?.refreshToken && !renewalTimers.has(sessionKeyId(key))) {
        scheduleRenewal(key, session, e.origin);
    }

    // The refresh token stays here: the page has no use for it, and this
    // frame does every renewal and every mint.
    window.parent.postMessage(
        { type: 'privasys:session', session: session ? { ...session, refreshToken: undefined } : null },
        e.origin,
    );
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
    else reply({ accessToken: after.token });
    return;
}

export async function onClearSession({ e, key }: MessageContext): Promise<void> {
    // Signing out ends the session. The remembered wallets stay: each is
    // forgotten by itself, from the gate.
    if (key) {
        cancelRenewal(key);
        sessions.remove(key);
    }
    window.parent.postMessage(
        { type: 'privasys:session-cleared' },
        e.origin,
    );
}

// Mint an access token for another audience without replacing the
// session's own: a refresh_token grant with an explicit `scope` (RFC 6749
// section 6, plus the audience extension), under the session's own
// granted scopes, since the identity provider refuses a broader one. The
// rotated refresh token keeps the original scope, so later renewals still
// mint the session's audience.
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
    const scope = `audience:${audience} ${session.scope}`;
    let r = await refreshGrant(key, { parentOrigin: e.origin, notify: false, scope });
    // Another document rotated the token while this grant was in flight:
    // mint again from the one it stored.
    if (r.kind === 'adopted') r = await refreshGrant(key, { parentOrigin: e.origin, notify: false, scope });
    if (r.kind === 'granted') {
        reply({ accessToken: r.accessToken, expiresIn: r.expiresIn });
    } else if (r.kind === 'dead') {
        // Answered first: the page drops this frame on session-expired.
        reply({ error: 'session expired' });
        window.parent.postMessage({ type: 'privasys:session-expired', rpId: session.rpId }, e.origin);
    } else if (r.kind === 'failed') {
        reply({ error: r.error });
    } else {
        reply({ error: 'no refresh token in session' });
    }
}
