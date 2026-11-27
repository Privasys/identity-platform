// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The sealed transport: the one sealed session this frame holds for its
 * page, how it is established and resumed from the wallet's voucher, and the
 * request, stream and WebSocket messages that use it.
 */

import { PrivasysSession, type EncAuthEnvelope, type SealedWebSocket } from '../enclave-session';
import { sessionKeyId, type SessionKey } from '../session';
import { sessions, sessionForPage } from './page-scope';
import { renewalParents, needsRenewal, renewIfNeeded } from './renewal';
import type { MessageContext } from './router';
import { tokenSid } from './tokens';

// ── Sealed session-relay state (iframe-scoped) ───────────────────────────
//
// When the parent opts into session-relay we generate the SDK ephemeral
// P-256 keypair *here* (the private key never leaves the iframe origin).
// After the wallet attests the enclave and returns {session_id, enc_pub}
// over the broker, we derive K, instantiate a PrivasysSession, and expose
// a `privasys:session:request` postMessage RPC so the parent can issue
// sealed requests without ever seeing K or the plaintext envelope.

export interface PendingHandshake {
    appHost: string;
    /** The session this sealed handshake belongs to; its bearer token
     *  fetches the EncAuth vouchers. */
    key: SessionKey;
    sdkKeyPair: CryptoKeyPair;
    sdkPubB64: string;
}

export interface ActiveSession {
    appHost: string;
    sessionId: string;
    expiresAt: number;
    session: PrivasysSession;
}

/** The handshake a sign-in in progress started, and the sealed session
 *  this frame holds for its page. */
export const sealed: { pending: PendingHandshake | null; active: ActiveSession | null } = {
    pending: null,
    active: null,
};

// Readers of the sealed streams in flight, by the page's request id, so the
// page can stop one; and the ids it stopped before their response started.
export const streamReaders = new Map<string, ReadableStreamDefaultReader<Uint8Array>>();
export const cancelledStreams = new Set<string>();

/**
 * Make `session` this iframe's active sealed transport and forward its
 * liveness to the parent page (`privasys:session:state`), so the app can
 * show "reconnecting" or run the one-tap re-approval without tearing its
 * own state down. Every path that installs a session goes through here.
 */
export function adoptSession(
    appHost: string,
    session: PrivasysSession,
    expiresAt: number,
    parentOrigin: string,
): void {
    sealed.active = { appHost, sessionId: session.sessionId, expiresAt, session };
    session.onStateChange = (state) => {
        if (sealed.active?.session !== session) return;
        window.parent.postMessage({ type: 'privasys:session:state', ...state }, parentOrigin);
    };
}
// Sealed WebSockets the parent opened, keyed by the parent's correlation id.
// The WebSocket lives here (where K is); the parent bridges send/recv over
// postMessage. Cleaned up on close.
export const activeWebSockets = new Map<number, SealedWebSocket>();

/**
 * Does the holder already allow this app to spend their credits?
 *
 * Matched by HOST, the only identifier a browser has: the app id is derived
 * from the attested certificate (OID 3.6) inside the wallet ceremony, which
 * is precisely the thing that has not happened yet when this is asked.
 *
 * Fails OPEN. A consent lookup that cannot be made is not evidence of a
 * missing consent, and refusing a silent resume on a transport hiccup would
 * cost the holder their session to answer a question they already answered.
 */
export async function hasSpendConsent(key: SessionKey, appHost: string): Promise<boolean> {
    const session = sessions.get(key);
    if (!session?.token) return true;
    try {
        const resp = await fetch(`${globalThis.location.origin}/spend/consents`, {
            headers: { Authorization: `Bearer ${session.token}` },
            cache: 'no-store',
        });
        if (!resp.ok) return true;
        const body = await resp.json() as { consents?: { app_host?: string; revoked_at?: string }[] };
        const host = appHost.toLowerCase();
        return (body.consents ?? []).some(
            (c) => !c.revoked_at && (c.app_host ?? '').toLowerCase() === host,
        );
    } catch {
        return true;
    }
}

/**
 * Build the EncAuth voucher fetcher for silent rebind / cold resume.
 * Reads the freshest bearer token of the session `key` names at call time (renewal may have rotated it since install) and
 * fetches the wallet-signed envelope from the IdP. Returns null when
 * there is no session, no `sid` claim, or no stored voucher — the
 * caller then falls back to a wallet ceremony.
 */
export function makeGetEncAuth(key: SessionKey, host: string): () => Promise<EncAuthEnvelope | null> {
    return async () => {
        let session = sessions.get(key);
        if (!session?.token) return null;
        // A tab that wakes from a long sleep rebinds BEFORE its renewal
        // heartbeat has run: the stored access token is already expired, the
        // IdP would refuse the voucher fetch, and the rebind would fail for
        // no good reason. Renew first (under the cross-document lock; a
        // no-op when another document already did).
        if (session.refreshToken && needsRenewal(session.token)) {
            session = await renewIfNeeded(key, renewalParents.get(sessionKeyId(key))?.parentOrigin ?? '', false) ?? session;
            if (!session?.token) return null;
        }
        const sid = tokenSid(session.token);
        if (!sid) return null;
        // Select the voucher for THIS enclave by host. The browser can't compute
        // app_id (it never attests), so host is the resume selector; the enclave
        // re-verifies the voucher's app_id at consumption. Multi-app sessions
        // hold one voucher per host on the same sid — without the selector the
        // IdP would return the most-recent (wrong) one.
        const url =
            `${globalThis.location.origin}/sessions/${encodeURIComponent(sid)}/encauth` +
            (host ? `?host=${encodeURIComponent(host)}` : '');
        // cache: 'no-store': a cached response for this URL (one heuristically
        // cached for lack of Cache-Control) would be replayed forever, and
        // every silent resume would fail 'unavailable'.
        const resp = await fetch(url, {
            headers: { Authorization: `Bearer ${session.token}` },
            cache: 'no-store',
        });
        if (!resp.ok) return null;
        return (await resp.json()) as EncAuthEnvelope;
    };
}

// ── Same-device sealed-binding recovery ──────────────────────────────────
//
// After a same-device wallet ceremony the browser is BACKGROUNDED while the
// user is in the wallet app, and the voucher the sealed binding needs is
// uploaded around the moment they switch back. iOS suspends timers in a
// backgrounded tab, so a short burst of immediate retries is spent on an
// upload that does not exist yet — leaving the sealed session anonymous.
// The enclave only asserts X-Privasys-Sub for a voucher-backed bootstrap
// (sessionrelay.go), so the app then answers 401 "authentication required"
// even though the JWT session is perfectly good.

/** Total budget for picking up the wallet's EncAuth voucher after a
 *  same-device ceremony. Generous: it must span the app switch back. */
export const SAME_DEVICE_VOUCHER_WINDOW_MS = 90_000;

/** Budget for the voucher after an ordinary (cross-device) ceremony. The
 *  wallet uploads it before relaying the result, so it is normally there on
 *  the first try; the window covers an older wallet that uploads after. */
export const CEREMONY_VOUCHER_WINDOW_MS = 20_000;

/**
 * Establish the sealed session from the wallet's EncAuth voucher, retrying
 * until `windowMs` runs out. A voucher-backed bootstrap is the only kind the
 * enclave asserts the caller's identity on (X-Privasys-Sub), so this is what
 * `connect()` must hand the app: the wallet's own bootstrap carries no
 * identity and an app that attributes callers answers it 401.
 *
 * `no-voucher` (not uploaded yet) and `unavailable` (transport blip) are
 * transient here; `rate-limited` waits out the enclave's window once;
 * `rejected` (the enclave refused the voucher outright) ends the wait.
 */
export async function resumeVoucherSession(
    appHost: string,
    key: SessionKey,
    windowMs: number,
): Promise<PrivasysSession | null> {
    const getEncAuth = makeGetEncAuth(key, appHost);
    const deadline = Date.now() + windowMs;
    let backoff = 1_000;
    while (Date.now() < deadline) {
        // Only spend attempts while the page is in the foreground; that is
        // when the upload lands (iOS suspends a backgrounded tab's timers).
        await waitForForeground(deadline);
        const res = await PrivasysSession.resume({ host: appHost, getEncAuth });
        if (!('error' in res)) return res.session;
        if (res.error === 'rejected') return null;
        const wait = res.error === 'rate-limited' ? 15_000 : backoff;
        await new Promise((r) => setTimeout(r, wait));
        backoff = Math.min(backoff * 1.5, 5_000);
    }
    return null;
}

/** How long an anonymous session keeps looking for the wallet's voucher in
 *  the background. Past it, an app's 401 still makes the session look. */
export const IDENTIFY_WINDOW_MS = 10 * 60_000;

/**
 * Keep trying to identify an anonymous session (the wallet's own bootstrap)
 * from the wallet's voucher, so the app learns who the caller is as soon as
 * the voucher lands, not only after the enclave forgets the session. Stops
 * once the session is no longer this frame's active one.
 */
export function identifyInBackground(session: PrivasysSession): void {
    const deadline = Date.now() + IDENTIFY_WINDOW_MS;
    let wait = 3_000;
    const current = () => sealed.active?.session === session && session.isAnonymous && Date.now() < deadline;
    const attempt = async (): Promise<void> => {
        if (!current()) return;
        await waitForForeground(deadline);
        if (!current()) return;
        if (await session.identify()) return;
        wait = Math.min(wait * 1.5, 30_000);
        setTimeout(() => { void attempt(); }, wait);
    };
    setTimeout(() => { void attempt(); }, wait);
}

/** Resolve once the document is foregrounded, or after a short poll cap so
 *  we still retry if `visibilitychange` never fires. Never resolves later
 *  than `deadline`. */
export function waitForForeground(deadline: number): Promise<void> {
    if (typeof document === 'undefined' || document.visibilityState === 'visible') {
        return Promise.resolve();
    }
    return new Promise((resolve) => {
        const finish = () => {
            document.removeEventListener('visibilitychange', onVisibility);
            clearTimeout(timer);
            resolve();
        };
        const onVisibility = () => {
            if (document.visibilityState === 'visible') finish();
        };
        document.addEventListener('visibilitychange', onVisibility);
        const timer = setTimeout(finish, Math.max(0, Math.min(5_000, deadline - Date.now())));
    });
}

// ── Voucher push (one-tap wallet approval for an additional/changed app) ──
//
// Triggers a `voucher-only` wallet push via the broker and polls the IdP
// until a NEW EncAuth voucher for `appHost` lands. Throws with 'no-session',
// 'no-push', 'timeout' or a transport message. Shared by the parent-facing
// `privasys:voucher-request` RPC and the connect-mode approve flow.
export async function requestVoucherPush(opts: {
    key: SessionKey;
    appName: string;
    appHost: string;
}): Promise<void> {
    const session = sessions.get(opts.key);
    if (!session?.token) throw new Error('no-session');
    if (!session.pushToken || !session.brokerUrl) throw new Error('no-push');
    const sid = tokenSid(session.token);
    if (!sid) throw new Error('no-session');
    const appHost = opts.appHost.trim();
    if (!appHost) throw new Error('appHost required');

    // Snapshot the existing voucher (if any) so we can tell a NEWLY issued
    // one apart — a stale voucher the enclave already refused would
    // otherwise satisfy the poll instantly and change nothing.
    const encauthURL =
        `${globalThis.location.origin}/sessions/${encodeURIComponent(sid)}/encauth` +
        `?host=${encodeURIComponent(appHost)}`;
    const fetchEnvelope = async (): Promise<string | null> => {
        // no-store: see makeGetEncAuth — a poisoned cache entry for this URL
        // would blind the new-voucher poll permanently.
        const r = await fetch(encauthURL, {
            headers: { Authorization: `Bearer ${session.token}` },
            cache: 'no-store',
        });
        if (!r.ok) return null;
        const body = await r.json().catch(() => null);
        return body ? JSON.stringify(body) : null;
    };
    const before = await fetchEnvelope();

    // A throwaway SDK keypair the wallet uses to complete the enclave
    // bootstrap and READ its enc_pub (which the voucher binds). The browser
    // mints its own fresh keypair when it later resumes the sealed session,
    // so this pub is discarded after enc_pub is read.
    const { sdkPubB64 } = await generateSdkKeyPair();

    // Trigger the wallet push via the broker (same endpoint the
    // returning-user sign-in uses), mode "voucher-only".
    const brokerBase = String(session.brokerUrl)
        .replace('wss://', 'https://')
        .replace('ws://', 'http://')
        .replace(/\/relay\/?$/, '');
    const notifyResp = await fetch(`${brokerBase}/notify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            pushToken: session.pushToken,
            // The broker requires a sessionId; the voucher flow has no WS
            // relay, so this is just a correlation id.
            sessionId: `voucher-${Date.now()}-${Math.random().toString(36).slice(2)}`,
            rpId: opts.key.rpId,
            appName: opts.appName || opts.key.rpId,
            // Bare host, NOT the full origin: the wallet uses this value
            // directly as the FIDO2 fetch host and separately prefixes
            // `https://` for clientDataJSON. Sending the scheme-prefixed
            // origin makes the wallet resolve host "https" and the
            // /fido2/authenticate call fails DNS.
            origin: globalThis.location.hostname,
            brokerUrl: session.brokerUrl,
            mode: 'voucher-only',
            appHost,
            sdkPub: sdkPubB64,
            // The exact IdP session the voucher must land on (the one this
            // poll reads) so the wallet writes to the same row.
            sid,
            clientId: opts.key.clientId,
        }),
    });
    if (!notifyResp.ok) throw new Error(`push failed: ${notifyResp.status}`);

    // Poll until a NEW voucher for this host lands (the wallet POSTs it to
    // /sessions/encauth). Human-scale deadline.
    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 2_500));
        const now = await fetchEnvelope();
        if (now && now !== before) return;
    }
    throw new Error('timeout');
}

export async function generateSdkKeyPair(): Promise<{ keyPair: CryptoKeyPair; sdkPubB64: string }> {
    const keyPair = (await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        false, // non-extractable: private key stays in this origin's WebCrypto store
        ['deriveBits'],
    )) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    if (raw.byteLength !== 65 || raw[0] !== 0x04) {
        throw new Error('frame-host: unexpected SEC1 encoding for SDK pubkey');
    }
    let s = '';
    for (let i = 0; i < raw.byteLength; i++) s += String.fromCharCode(raw[i]);
    const sdkPubB64 = btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return { keyPair, sdkPubB64 };
}

/**
 * Normalise an enclave-supplied expiry to epoch ms. The wire contract
 * uses epoch seconds (crypto-contract §3); older Go enclaves sent epoch
 * ms. Values below 1e12 cannot be a sane epoch-ms after Sep 2001, so
 * they are treated as seconds.
 */
export function normalizeEpochMs(v: number | undefined): number {
    if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) return 0;
    return v < 1e12 ? v * 1000 : v;
}

export async function installSessionRelay(
    binding: { sessionId: string; encPub: string; expiresAt?: number },
    parentOrigin: string,
): Promise<void> {
    if (!sealed.pending) {
        console.warn('[frame-host] sessionRelay returned without pending handshake — ignoring');
        return;
    }
    const { sdkKeyPair, appHost, key } = sealed.pending;
    sealed.pending = null;
    const expiresAtMs = normalizeEpochMs(binding.expiresAt);
    try {
        const session = await PrivasysSession.fromHandshake({
            host: appHost,
            sessionId: binding.sessionId,
            sdkPrivateKey: sdkKeyPair.privateKey,
            encPub: binding.encPub,
            // Silent rebind: when the enclave forgets this session (idle
            // TTL, restart with the same identity) the next request's
            // unsealed 401 triggers a voucher-based re-bootstrap with no
            // wallet involvement.
            getEncAuth: makeGetEncAuth(key, appHost),
            // The wallet's own bootstrap: the enclave does not know who
            // the caller is until the session is rebuilt from the voucher.
            anonymous: true,
        });
        adoptSession(appHost, session, expiresAtMs, parentOrigin);
        identifyInBackground(session);
        window.parent.postMessage(
            {
                type: 'privasys:session:ready',
                sessionId: binding.sessionId,
                appHost,
                expiresAt: expiresAtMs,
            },
            parentOrigin,
        );
    } catch (err) {
        console.error('[frame-host] failed to derive sealed session:', err);
        window.parent.postMessage(
            {
                type: 'privasys:session:error',
                error: err instanceof Error ? err.message : String(err),
            },
            parentOrigin,
        );
    }
}

// Incremental multi-app attestation: ask the wallet — via push — to
// voucher an ADDITIONAL enclave host for the live session, then wait
// for the (new) voucher to appear at the IdP. One biometric approval
// on the phone; no WebAuthn ceremony, no sign-out. The parent then
// resumes the sealed session for that host as usual.
export async function onVoucherRequest({ e, data, key }: MessageContext): Promise<void> {
    const id = data.id;
    const reply = (payload: Record<string, unknown>) =>
        window.parent.postMessage(
            { type: 'privasys:voucher-request:response', id, ...payload },
            e.origin,
        );
    try {
        if (!key || !(await sessionForPage(key, e.origin))) throw new Error('no-session');
        await requestVoucherPush({
            key,
            appName: String(data.appName || key.rpId),
            appHost: String(data.appHost || ''),
        });
        reply({ ok: true });
    } catch (err) {
        reply({ error: (err as Error).message });
    }
    return;
}

// Sealed session-relay RPC. The parent serialises the request as
// {method, path, body?} and we relay it through PrivasysSession.request
// (CBOR-sealed AES-256-GCM over fetch). Only the iframe holds K, so the
// parent can never inspect or replay sealed traffic.
export async function onSessionRequest({ e, data }: MessageContext): Promise<void> {
    const id = data.id;
    const reply = (payload: Record<string, unknown>) =>
        window.parent.postMessage({ type: 'privasys:session:response', id, ...payload }, e.origin);
    if (!sealed.active) {
        reply({ error: 'no active session' });
        return;
    }
    // No pre-emptive expiry gate here: with the sliding enclave TTL an
    // active session never wall-clock-expires, and a forgotten one
    // comes back as an unsealed 401 that PrivasysSession.request()
    // resolves via EncAuth silent rebind.
    try {
        const method = String(data.method || 'GET').toUpperCase();
        const path = String(data.path || '/');
        const body = data.body as unknown;
        const init = (data.init as RequestInit | undefined) ?? undefined;
        const resp = await sealed.active.session.request(method, path, body, init);
        const headers: Record<string, string> = {};
        resp.headers.forEach((v, k) => { headers[k] = v; });
        reply({
            status: resp.status,
            headers,
            body: resp.body,
            sealed: resp.sealed,
        });
    } catch (err) {
        reply({ error: err instanceof Error ? err.message : String(err) });
    }
}

// Cold resume: re-establish a sealed session purely from the stored
// EncAuth voucher — no wallet ceremony, no push. Used by the parent
// after a page reload, when the OIDC session restored via SSO but
// the iframe-resident sealed session (deliberately never persisted)
// is gone. Idempotent: an already-active session for the same
// appHost is returned as-is.
export async function onSessionResume({ e, data, key }: MessageContext): Promise<void> {
    const id = data.id;
    const reply = (payload: Record<string, unknown>) =>
        window.parent.postMessage({ type: 'privasys:session:resume:response', id, ...payload }, e.origin);
    const appHost = String(data.appHost || '');
    if (!appHost || typeof data.rpId !== 'string' || !data.rpId) {
        reply({ error: 'appHost and rpId required' });
        return;
    }
    if (!key || !(await sessionForPage(key, e.origin))) {
        reply({ error: 'no-session' });
        return;
    }
    if (sealed.active && sealed.active.appHost === appHost) {
        reply({ sessionId: sealed.active.sessionId, appHost, expiresAt: sealed.active.expiresAt });
        return;
    }
    // An app that asks to spend the holder's credits must be ALLOWED to,
    // and the only screen that asks is the wallet ceremony. A returning
    // holder resumes silently, so without this a newly deployed app could
    // never be paid for: it would ask on every sign-in and be asked on
    // none, and every priced call would fail 402 with nothing to click.
    // Refusing the SILENT resume hands the gate back
    // to connect(), which runs the ceremony, the wallet shows the spend
    // row, and the answer is recorded once.
    //
    // Fails OPEN: a consent lookup that cannot be made must never cost
    // someone their own session.
    if (data.spend && !(await hasSpendConsent(key, appHost))) {
        reply({ error: 'rejected', reason: 'spend-consent-required' });
        return;
    }
    const getEncAuth = makeGetEncAuth(key, appHost);
    const result = await PrivasysSession.resume({ host: appHost, getEncAuth });
    if ('error' in result) {
        // 'no-voucher'    → user never completed a sealed sign-in here
        // 'rejected'      → enclave refused the voucher; a wallet
        //                   ceremony is required. `reason` (when the
        //                   enclave said why) distinguishes
        //                   'workload-changed' (the app was updated)
        //                   from 'enc-changed' (the platform changed)
        //                   so the tab can explain the wake.
        // 'unavailable'   → transport failure, worth retrying
        reply({ error: result.error, reason: result.reason });
        return;
    }
    adoptSession(appHost, result.session, 0, e.origin);
    reply({ sessionId: result.session.sessionId, appHost, expiresAt: 0 });
    return;
}

// Sealed streaming RPC. The parent posts a single
// `privasys:session:stream-request`; the iframe replies with one
// `privasys:session:stream-start` (carrying status + headers) followed
// by zero or more `privasys:session:stream-chunk` messages and finally
// `privasys:session:stream-end` (or `privasys:session:stream-error`).
// A stream the page stopped reading: its reader is cancelled, which
// ends the sealed response. A cancel that arrives before the response
// has started is remembered and applied when it starts.
export async function onSessionStreamCancel({ data }: MessageContext): Promise<void> {
    const id = String(data.id ?? '');
    const reader = streamReaders.get(id);
    if (reader) void reader.cancel().catch(() => undefined);
    else if (id && cancelledStreams.size < 64) cancelledStreams.add(id);
    return;
}

export async function onSessionStreamRequest({ e, data }: MessageContext): Promise<void> {
    const id = data.id;
    const post = (type: string, payload: Record<string, unknown> = {}) =>
        window.parent.postMessage({ type, id, ...payload }, e.origin);
    if (!sealed.active) {
        post('privasys:session:stream-error', { error: 'no active session' });
        return;
    }
    try {
        const method = String(data.method || 'POST').toUpperCase();
        const path = String(data.path || '/');
        const body = data.body as unknown;
        const init = (data.init as RequestInit | undefined) ?? undefined;
        const resp = await sealed.active.session.stream(method, path, body, init);
        const headers: Record<string, string> = {};
        resp.headers.forEach((v, k) => { headers[k] = v; });
        post('privasys:session:stream-start', { status: resp.status, headers, sealed: resp.sealed });
        const reader = resp.body.getReader();
        const streamId = String(id ?? '');
        streamReaders.set(streamId, reader);
        if (cancelledStreams.delete(streamId)) void reader.cancel().catch(() => undefined);
        try {
            for (;;) {
                const { value, done } = await reader.read();
                if (done) break;
                if (value && value.byteLength > 0) {
                    post('privasys:session:stream-chunk', { chunk: value });
                }
            }
            post('privasys:session:stream-end');
        } catch (err) {
            post('privasys:session:stream-error', {
                error: err instanceof Error ? err.message : String(err),
            });
        } finally {
            streamReaders.delete(streamId);
        }
    } catch (err) {
        post('privasys:session:stream-error', {
            error: err instanceof Error ? err.message : String(err),
        });
    }
}

// ── Sealed WebSocket bridge ──────────────────────────────────────────
// Only the iframe holds K, so the sealed WebSocket runs HERE and the
// parent drives it over postMessage. The parent posts
// `privasys:session:ws-open {id, path}`; we reply `ws-open-ack` (or
// `ws-error`) and then relay `ws-message` / `ws-close` / `ws-error`
// events. The parent posts `ws-send {id, data}` and `ws-close {id}`.
export async function onSessionWsOpen({ e, data }: MessageContext): Promise<void> {
    const id = data.id as number;
    const post = (type: string, payload: Record<string, unknown> = {}) =>
        window.parent.postMessage({ type, id, ...payload }, e.origin);
    if (!sealed.active) {
        post('privasys:session:ws-error', { error: 'no active session' });
        post('privasys:session:ws-close', { code: 1006, reason: 'no active session' });
        return;
    }
    if (activeWebSockets.has(id)) {
        post('privasys:session:ws-error', { error: 'websocket id already in use' });
        return;
    }
    let ws: SealedWebSocket;
    try {
        ws = sealed.active.session.openWebSocket(String(data.path || '/'));
    } catch (err) {
        post('privasys:session:ws-error', { error: err instanceof Error ? err.message : String(err) });
        post('privasys:session:ws-close', { code: 1006, reason: 'open failed' });
        return;
    }
    activeWebSockets.set(id, ws);
    ws.onMessage((d) => post('privasys:session:ws-message', { data: d }));
    ws.onError((err) => post('privasys:session:ws-error', { error: err.message }));
    ws.onClose((info) => {
        activeWebSockets.delete(id);
        post('privasys:session:ws-close', { code: info.code, reason: info.reason, wasClean: info.wasClean });
    });
    ws.ready.then(
        () => post('privasys:session:ws-open-ack'),
        (err) => {
            activeWebSockets.delete(id);
            post('privasys:session:ws-error', { error: err instanceof Error ? err.message : String(err) });
        },
    );
    return;
}

export async function onSessionWsSend({ data }: MessageContext): Promise<void> {
    const ws = activeWebSockets.get(data.id as number);
    if (ws) {
        try { ws.send(data.data as Uint8Array); } catch { /* closed mid-send */ }
    }
    return;
}

export async function onSessionWsClose({ data }: MessageContext): Promise<void> {
    const id = data.id as number;
    const ws = activeWebSockets.get(id);
    if (ws) {
        activeWebSockets.delete(id);
        ws.close(typeof data.code === 'number' ? data.code : 1000, String(data.reason ?? ''));
    }
    return;
}
