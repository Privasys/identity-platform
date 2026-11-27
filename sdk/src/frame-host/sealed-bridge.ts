// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The sealed transport: one sealed session per enclave host, established
 * from the wallet's approval (the EncAuth voucher) for the page's session,
 * and the request, stream and WebSocket messages that use them. The session
 * keys never leave this frame.
 */

import { PrivasysSession, type EncAuthEnvelope, type SealedWebSocket } from '../enclave-session';
import { sessionKeyId, type SessionKey } from '../session';
import type { AuthSession } from '../types';
import { sessions, sessionForPage } from './page-scope';
import { needsRenewal, onWatchedSessionChange, renewIfNeeded, watches } from './renewal';
import type { MessageContext } from './router';
import { tokenSid } from './tokens';

/** A sealed session this frame holds, and the sign-in it was made under. */
interface SealedEntry {
    session: PrivasysSession;
    /** The session whose voucher made it, and that sign-in's `sid`. */
    keyId: string;
    sid: string | null;
    parentOrigin: string;
}

/** The sealed sessions this frame holds for its page, by enclave host. */
export const sealedSessions = new Map<string, SealedEntry>();

/** Resumes in flight, by session and host: concurrent asks share one bootstrap. */
const resuming = new Map<string, Promise<ResumeResult>>();

// Readers of the sealed streams in flight, by the page's request id, so the
// page can stop one; and the ids it stopped before their response started.
export const streamReaders = new Map<string, { host: string; reader: ReadableStreamDefaultReader<Uint8Array> }>();
export const cancelledStreams = new Set<string>();

// Sealed WebSockets the page opened, by the page's id. The socket lives here
// (where the keys are); the page drives it over postMessage.
export const activeWebSockets = new Map<number, { host: string; ws: SealedWebSocket }>();

/** An enclave host as a page names it: a DNS name, with an optional port. */
export function sanitiseHost(raw: unknown): string | null {
    if (typeof raw !== 'string') return null;
    const host = raw.trim().toLowerCase();
    return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d{1,5})?$/.test(host) && host.length <= 253
        ? host
        : null;
}

/** Tell the page how the sealed session of `host` is doing. */
function postState(host: string, parentOrigin: string, state: { status: string; reason?: string }): void {
    try {
        window.parent.postMessage({ type: 'privasys:session:state', host, ...state }, parentOrigin);
    } catch { /* parent gone */ }
}

/**
 * Make `session` the sealed session of `host` and forward its liveness to the
 * page, so the page can show "reconnecting" or ask for a new approval without
 * tearing its own state down.
 */
export function adoptSession(host: string, session: PrivasysSession, key: SessionKey, sid: string | null, parentOrigin: string): void {
    sealedSessions.set(host, { session, keyId: sessionKeyId(key), sid, parentOrigin });
    session.onStateChange = (state) => {
        if (sealedSessions.get(host)?.session !== session) return;
        postState(host, parentOrigin, state);
    };
}

// The sealed sessions belong to the sign-in that made them: a sign-out, an
// expiry or another person's sign-in ends them.
onWatchedSessionChange((key, current: AuthSession | undefined) => {
    const keyId = sessionKeyId(key);
    const sid = current ? tokenSid(current.token) : null;
    for (const [host, entry] of sealedSessions) {
        if (entry.keyId !== keyId || (current && entry.sid === sid)) continue;
        sealedSessions.delete(host);
        postState(host, entry.parentOrigin, { status: 'signed-out', reason: current ? 'signed-in-again' : 'signed-out' });
    }
});

/**
 * Does the holder already allow this app to spend their credits?
 *
 * Matched by host, the only identifier a browser has: the app id is derived
 * from the attested certificate inside the wallet ceremony.
 *
 * Fails open: a consent lookup that cannot be made is not evidence of a
 * missing consent.
 */
export async function hasSpendConsent(key: SessionKey, host: string): Promise<boolean> {
    const session = sessions.get(key);
    if (!session?.token) return true;
    try {
        const resp = await fetch(`${globalThis.location.origin}/spend/consents`, {
            headers: { Authorization: `Bearer ${session.token}` },
            cache: 'no-store',
        });
        if (!resp.ok) return true;
        const body = await resp.json() as { consents?: { app_host?: string; revoked_at?: string }[] };
        return (body.consents ?? []).some(
            (c) => !c.revoked_at && (c.app_host ?? '').toLowerCase() === host,
        );
    } catch {
        return true;
    }
}

/**
 * The EncAuth voucher fetcher for a host. Reads the freshest bearer token of
 * the session `key` names at call time (renewal may have rotated it) and
 * fetches the wallet-signed envelope from the identity provider. Returns null
 * when there is no session, no `sid` claim or no stored voucher.
 */
export function makeGetEncAuth(key: SessionKey, host: string): () => Promise<EncAuthEnvelope | null> {
    return async () => {
        let session = sessions.get(key);
        if (!session?.token) return null;
        // A tab that wakes from a long sleep may rebind before its renewal
        // heartbeat has run; the expired token would be refused.
        if (session.refreshToken && needsRenewal(session.token)) {
            session = await renewIfNeeded(key, watches.get(sessionKeyId(key))?.parentOrigin ?? '') ?? session;
            if (!session?.token) return null;
        }
        const sid = tokenSid(session.token);
        if (!sid) return null;
        // One voucher per host on the same sid: the host selects it. The
        // enclave re-verifies the voucher's app id when it consumes it.
        // no-store: a cached answer would be replayed forever.
        const resp = await fetch(
            `${globalThis.location.origin}/sessions/${encodeURIComponent(sid)}/encauth?host=${encodeURIComponent(host)}`,
            { headers: { Authorization: `Bearer ${session.token}` }, cache: 'no-store' },
        );
        if (!resp.ok) return null;
        return (await resp.json()) as EncAuthEnvelope;
    };
}

/** How long to wait for the wallet's voucher after a same-device sign-in,
 *  where the upload lands as the person switches back from the wallet. */
export const SAME_DEVICE_VOUCHER_WINDOW_MS = 90_000;

/** How long to wait for the voucher after any other wallet sign-in. */
export const CEREMONY_VOUCHER_WINDOW_MS = 20_000;

export type ResumeResult =
    | { session: PrivasysSession }
    | { error: 'no-voucher' | 'rejected' | 'unavailable' | 'rate-limited'; reason?: string };

/**
 * Establish the sealed session of `host` from the wallet's voucher. With a
 * window, a missing voucher (not uploaded yet) and a transport blip are
 * retried until it runs out, and the enclave's rate limit is waited out;
 * a refusal ends the wait. Only a voucher-backed bootstrap tells the enclave
 * who the caller is.
 */
export async function resumeSealed(host: string, key: SessionKey, windowMs: number): Promise<ResumeResult> {
    const getEncAuth = makeGetEncAuth(key, host);
    const deadline = Date.now() + windowMs;
    let backoff = 1_000;
    for (;;) {
        // Attempts are spent while the page is in the foreground, which is
        // when the voucher upload lands (iOS suspends a background tab).
        await waitForForeground(deadline);
        const res = await PrivasysSession.resume({ host, getEncAuth });
        if (!('error' in res) || res.error === 'rejected') return res;
        const wait = res.error === 'rate-limited' ? 15_000 : backoff;
        if (Date.now() + wait > deadline) return res;
        await new Promise((r) => setTimeout(r, wait));
        backoff = Math.min(backoff * 1.5, 5_000);
    }
}

/** Resolve once the document is foregrounded, after a short poll cap, or at
 *  `deadline`, whichever comes first. */
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

/**
 * Ask the holder's wallet, by push, to approve one more enclave host for the
 * current sign-in, and wait until the new voucher lands. Throws 'no-session',
 * 'no-push', 'timeout' or a transport message.
 */
export async function requestVoucherPush(opts: { key: SessionKey; appName: string; host: string }): Promise<void> {
    const session = sessions.get(opts.key);
    if (!session?.token) throw new Error('no-session');
    if (!session.pushToken || !session.brokerUrl) throw new Error('no-push');
    const sid = tokenSid(session.token);
    if (!sid) throw new Error('no-session');

    // The voucher there before the push, so a new one can be told apart: a
    // stale voucher the enclave already refused must not end the wait.
    const encauthURL =
        `${globalThis.location.origin}/sessions/${encodeURIComponent(sid)}/encauth` +
        `?host=${encodeURIComponent(opts.host)}`;
    const fetchEnvelope = async (): Promise<string | null> => {
        const r = await fetch(encauthURL, {
            headers: { Authorization: `Bearer ${session.token}` },
            cache: 'no-store',
        });
        if (!r.ok) return null;
        const body = await r.json().catch(() => null);
        return body ? JSON.stringify(body) : null;
    };
    const before = await fetchEnvelope();

    // A throwaway key the wallet completes the enclave bootstrap with, to
    // read the enc_pub the voucher binds. The sealed session itself is made
    // with a fresh key when it resumes.
    const { sdkPubB64 } = await generateSdkKeyPair();

    const brokerBase = String(session.brokerUrl)
        .replace('wss://', 'https://')
        .replace('ws://', 'http://')
        .replace(/\/relay\/?$/, '');
    const notifyResp = await fetch(`${brokerBase}/notify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            pushToken: session.pushToken,
            // The broker requires a session id; a voucher push has no relay,
            // so this only correlates.
            sessionId: `voucher-${Date.now()}-${Math.random().toString(36).slice(2)}`,
            rpId: opts.key.rpId,
            appName: opts.appName || opts.key.rpId,
            // A bare host: the wallet fetches /fido2 from it and prefixes
            // https:// for clientDataJSON itself.
            origin: globalThis.location.hostname,
            brokerUrl: session.brokerUrl,
            mode: 'voucher-only',
            appHost: opts.host,
            sdkPub: sdkPubB64,
            // The identity provider session the voucher must land on.
            sid,
            clientId: opts.key.clientId,
        }),
    });
    if (!notifyResp.ok) throw new Error(`push failed: ${notifyResp.status}`);

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
        false, // non-extractable: the private key stays in this origin
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

// One tap in the wallet approves one more host for the session; the page
// then resumes the host's sealed session.
export async function onVoucherRequest({ e, data, key }: MessageContext): Promise<void> {
    const id = data.id;
    const reply = (payload: Record<string, unknown>) =>
        window.parent.postMessage({ type: 'privasys:voucher-request:response', id, ...payload }, e.origin);
    const host = sanitiseHost(data.host);
    try {
        if (!host) throw new Error('host required');
        if (!key || !(await sessionForPage(key, e.origin))) throw new Error('no-session');
        await requestVoucherPush({ key, appName: String(data.appName || ''), host });
        reply({ ok: true });
    } catch (err) {
        reply({ error: (err as Error).message });
    }
}

// Establish the sealed session of a host from the stored voucher: no
// ceremony, no push. An established one is answered as it is. `waitMs` (just
// after a sign-in that approved the host) waits for the voucher to land.
export async function onSessionResume({ e, data, key }: MessageContext): Promise<void> {
    const id = data.id;
    const host = sanitiseHost(data.host);
    const reply = (payload: Record<string, unknown>) =>
        window.parent.postMessage({ type: 'privasys:session:resume:response', id, host, ...payload }, e.origin);
    if (!host) {
        reply({ error: 'host required' });
        return;
    }
    const session = await sessionForPage(key, e.origin);
    if (!key || !session) {
        reply({ error: 'no-session' });
        return;
    }
    const existing = sealedSessions.get(host);
    if (existing) {
        reply({ sessionId: existing.session.sessionId });
        return;
    }
    // An app that asks to spend the holder's credits must be allowed to, and
    // only the wallet asks: a silent resume is refused until it has.
    if (data.spend && !(await hasSpendConsent(key, host))) {
        reply({ error: 'rejected', reason: 'spend-consent-required' });
        return;
    }
    const windowMs = Math.min(Math.max(Number(data.waitMs) || 0, 0), SAME_DEVICE_VOUCHER_WINDOW_MS);
    const resumeId = `${sessionKeyId(key)}|${host}`;
    let pending = resuming.get(resumeId);
    if (!pending) {
        pending = resumeSealed(host, key, windowMs).finally(() => resuming.delete(resumeId));
        resuming.set(resumeId, pending);
    }
    const result = await pending;
    if ('error' in result) {
        // no-voucher: the wallet never approved this host for this sign-in.
        // rejected: the enclave refused the voucher; `reason` says why
        // (workload-changed, enc-changed, voucher-expired, voucher-invalid).
        // unavailable, rate-limited: worth retrying.
        reply({ error: result.error, ...(result.reason ? { reason: result.reason } : {}) });
        return;
    }
    if (!sealedSessions.has(host)) adoptSession(host, result.session, key, tokenSid(session.token), e.origin);
    reply({ sessionId: sealedSessions.get(host)!.session.sessionId });
}

/** The sealed session a message names, or null. */
function sealedFor(data: { host?: unknown }): PrivasysSession | null {
    const host = sanitiseHost(data.host);
    return host ? sealedSessions.get(host)?.session ?? null : null;
}

// A sealed request: only this frame holds the keys, so the page never sees
// the sealed traffic.
export async function onSessionRequest({ e, data }: MessageContext): Promise<void> {
    const id = data.id;
    const reply = (payload: Record<string, unknown>) =>
        window.parent.postMessage({ type: 'privasys:session:response', id, ...payload }, e.origin);
    const sealed = sealedFor(data);
    if (!sealed) {
        reply({ error: 'no sealed session for this host' });
        return;
    }
    try {
        const resp = await sealed.request(
            String(data.method || 'GET').toUpperCase(),
            String(data.path || '/'),
            data.body as unknown,
            (data.init as RequestInit | undefined) ?? undefined,
        );
        const headers: Record<string, string> = {};
        resp.headers.forEach((v, k) => { headers[k] = v; });
        reply({ status: resp.status, headers, body: resp.body, sealed: resp.sealed });
    } catch (err) {
        reply({ error: err instanceof Error ? err.message : String(err) });
    }
}

// A stream the page stopped reading: its reader is cancelled, which ends the
// sealed response. A cancel that arrives before the response has started is
// remembered and applied when it starts.
export async function onSessionStreamCancel({ data }: MessageContext): Promise<void> {
    const id = String(data.id ?? '');
    const host = sanitiseHost(data.host);
    const slot = streamReaders.get(id);
    if (slot) {
        if (slot.host === host) void slot.reader.cancel().catch(() => undefined);
    } else if (id && cancelledStreams.size < 64) {
        cancelledStreams.add(id);
    }
}

// A sealed stream: one `stream-start` (status and headers), then chunks,
// then `stream-end` or `stream-error`.
export async function onSessionStreamRequest({ e, data }: MessageContext): Promise<void> {
    const id = data.id;
    const post = (type: string, payload: Record<string, unknown> = {}) =>
        window.parent.postMessage({ type, id, ...payload }, e.origin);
    const host = sanitiseHost(data.host);
    const sealed = sealedFor(data);
    if (!host || !sealed) {
        post('privasys:session:stream-error', { error: 'no sealed session for this host' });
        return;
    }
    try {
        const resp = await sealed.stream(
            String(data.method || 'POST').toUpperCase(),
            String(data.path || '/'),
            data.body as unknown,
            (data.init as RequestInit | undefined) ?? undefined,
        );
        const headers: Record<string, string> = {};
        resp.headers.forEach((v, k) => { headers[k] = v; });
        post('privasys:session:stream-start', { status: resp.status, headers, sealed: resp.sealed });
        const reader = resp.body.getReader();
        const streamId = String(id ?? '');
        streamReaders.set(streamId, { host, reader });
        if (cancelledStreams.delete(streamId)) void reader.cancel().catch(() => undefined);
        try {
            for (;;) {
                const { value, done } = await reader.read();
                if (done) break;
                if (value && value.byteLength > 0) post('privasys:session:stream-chunk', { chunk: value });
            }
            post('privasys:session:stream-end');
        } catch (err) {
            post('privasys:session:stream-error', { error: err instanceof Error ? err.message : String(err) });
        } finally {
            streamReaders.delete(streamId);
        }
    } catch (err) {
        post('privasys:session:stream-error', { error: err instanceof Error ? err.message : String(err) });
    }
}

// A sealed WebSocket: the page posts `ws-open {id, host, path}`; this frame
// answers `ws-open-ack` (or `ws-error`) and relays `ws-message`, `ws-close`
// and `ws-error`. The page posts `ws-send` and `ws-close` by id.
export async function onSessionWsOpen({ e, data }: MessageContext): Promise<void> {
    const id = data.id as number;
    const post = (type: string, payload: Record<string, unknown> = {}) =>
        window.parent.postMessage({ type, id, ...payload }, e.origin);
    const host = sanitiseHost(data.host);
    const sealed = sealedFor(data);
    if (!host || !sealed) {
        post('privasys:session:ws-error', { error: 'no sealed session for this host' });
        post('privasys:session:ws-close', { code: 1006, reason: 'no sealed session' });
        return;
    }
    if (activeWebSockets.has(id)) {
        post('privasys:session:ws-error', { error: 'websocket id already in use' });
        return;
    }
    let ws: SealedWebSocket;
    try {
        ws = sealed.openWebSocket(String(data.path || '/'));
    } catch (err) {
        post('privasys:session:ws-error', { error: err instanceof Error ? err.message : String(err) });
        post('privasys:session:ws-close', { code: 1006, reason: 'open failed' });
        return;
    }
    activeWebSockets.set(id, { host, ws });
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
}

export async function onSessionWsSend({ data }: MessageContext): Promise<void> {
    const slot = activeWebSockets.get(data.id as number);
    if (slot && slot.host === sanitiseHost(data.host)) {
        try { slot.ws.send(data.data as Uint8Array); } catch { /* closed mid-send */ }
    }
}

export async function onSessionWsClose({ data }: MessageContext): Promise<void> {
    const id = data.id as number;
    const slot = activeWebSockets.get(id);
    if (slot && slot.host === sanitiseHost(data.host)) {
        activeWebSockets.delete(id);
        slot.ws.close(typeof data.code === 'number' ? data.code : 1000, String(data.reason ?? ''));
    }
}
