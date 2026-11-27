// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * Frame host — runs inside the privasys.id/auth/ iframe.
 *
 * Listens for postMessage from the parent page, instantiates the AuthUI
 * to run the authentication ceremony, and relays results back via
 * postMessage. Sessions are stored in this origin's localStorage, which
 * the browser keeps apart for every site that embeds the frame, so a
 * session is shared by the tabs of one site and by no other site.
 *
 * The frame renews each session with the OIDC refresh_token grant before
 * its access token expires; only the sign-in itself needs the wallet.
 */

import { AuthUI } from './ui';
import { FRAME_SIZE_MESSAGE } from './frame-size';
import { sanitiseDisplayNames, sanitiseIcons, sanitiseOwn, sanitiseProviders, selectProviders, type OwnRegistration } from './providers';
import { sanitiseChoice, type GateState } from './gate-headless';
import { sanitiseTheme } from './theme';
import type { AuthUIConfig, SignInResult } from './ui';
import { SessionManager, SESSIONS_STORAGE_KEY, cleanDeviceLabel, deviceLabel, sessionKeyId, type DeviceHint, type PlatformScope, type SessionKey } from './session';
import type { AuthSession } from './types';
import { PrivasysSession, type EncAuthEnvelope, type SealedWebSocket } from './enclave-session';
import { parsePlatforms, platformScopeOf, type PlatformEntry } from './platforms';

const sessions = new SessionManager();

let activeUI: AuthUI | null = null;

// ── Sealed session-relay state (iframe-scoped) ───────────────────────────
//
// When the parent opts into session-relay we generate the SDK ephemeral
// P-256 keypair *here* (the private key never leaves the iframe origin).
// After the wallet attests the enclave and returns {session_id, enc_pub}
// over the broker, we derive K, instantiate a PrivasysSession, and expose
// a `privasys:session:request` postMessage RPC so the parent can issue
// sealed requests without ever seeing K or the plaintext envelope.

interface PendingHandshake {
    appHost: string;
    /** The session this sealed handshake belongs to; its bearer token
     *  fetches the EncAuth vouchers. */
    key: SessionKey;
    sdkKeyPair: CryptoKeyPair;
    sdkPubB64: string;
}

interface ActiveSession {
    appHost: string;
    sessionId: string;
    expiresAt: number;
    session: PrivasysSession;
}

let pendingHandshake: PendingHandshake | null = null;
let activeSession: ActiveSession | null = null;

// Readers of the sealed streams in flight, by the page's request id, so the
// page can stop one; and the ids it stopped before their response started.
const streamReaders = new Map<string, ReadableStreamDefaultReader<Uint8Array>>();
const cancelledStreams = new Set<string>();

/**
 * Make `session` this iframe's active sealed transport and forward its
 * liveness to the parent page (`privasys:session:state`), so the app can
 * show "reconnecting" or run the one-tap re-approval without tearing its
 * own state down. Every path that installs a session goes through here.
 */
function adoptSession(
    appHost: string,
    session: PrivasysSession,
    expiresAt: number,
    parentOrigin: string,
): void {
    activeSession = { appHost, sessionId: session.sessionId, expiresAt, session };
    session.onStateChange = (state) => {
        if (activeSession?.session !== session) return;
        window.parent.postMessage({ type: 'privasys:session:state', ...state }, parentOrigin);
    };
}
// Sealed WebSockets the parent opened, keyed by the parent's correlation id.
// The WebSocket lives here (where K is); the parent bridges send/recv over
// postMessage. Cleaned up on close.
const activeWebSockets = new Map<number, SealedWebSocket>();

/** JSON encoded as base64url (padding optional), or null when it is not. */
function b64urlJson(s: string): Record<string, unknown> | null {
    try {
        const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
        const bin = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), '='));
        const v: unknown = JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
        return v && typeof v === 'object' ? v as Record<string, unknown> : null;
    } catch {
        return null;
    }
}

/** The claims of a JWT, unverified (the identity provider signed it and
 *  checks it again on use), or null when unreadable. */
function jwtPayload(token: string): Record<string, unknown> | null {
    return b64urlJson(token.split('.')[1] ?? '');
}

/** The session id (`sid`) of an access token, or null. */
function tokenSid(token: string): string | null {
    const sid = jwtPayload(token)?.sid;
    return typeof sid === 'string' && sid ? sid : null;
}

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
async function hasSpendConsent(key: SessionKey, appHost: string): Promise<boolean> {
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
function makeGetEncAuth(key: SessionKey, host: string): () => Promise<EncAuthEnvelope | null> {
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
const SAME_DEVICE_VOUCHER_WINDOW_MS = 90_000;

/** Budget for the voucher after an ordinary (cross-device) ceremony. The
 *  wallet uploads it before relaying the result, so it is normally there on
 *  the first try; the window covers an older wallet that uploads after. */
const CEREMONY_VOUCHER_WINDOW_MS = 20_000;

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
async function resumeVoucherSession(
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
const IDENTIFY_WINDOW_MS = 10 * 60_000;

/**
 * Keep trying to identify an anonymous session (the wallet's own bootstrap)
 * from the wallet's voucher, so the app learns who the caller is as soon as
 * the voucher lands, not only after the enclave forgets the session.
 */
function identifyInBackground(session: PrivasysSession): void {
    const deadline = Date.now() + IDENTIFY_WINDOW_MS;
    let wait = 3_000;
    const attempt = async (): Promise<void> => {
        if (!session.isAnonymous || Date.now() >= deadline) return;
        await waitForForeground(deadline);
        if (await session.identify()) return;
        wait = Math.min(wait * 1.5, 30_000);
        setTimeout(() => { void attempt(); }, wait);
    };
    setTimeout(() => { void attempt(); }, wait);
}

/** Resolve once the document is foregrounded, or after a short poll cap so
 *  we still retry if `visibilitychange` never fires. Never resolves later
 *  than `deadline`. */
function waitForForeground(deadline: number): Promise<void> {
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

// ── Adopter-config sanitisers ────────────────────────────────────────────
//
// `pitch` and `methods` arrive from the adopter page via postMessage and
// are rendered inside this trusted origin, so they are strictly schema-
// checked: plain strings only (AuthUI renders them as text nodes), capped
// lengths, and a closed method vocabulary.

function sanitisePitch(raw: unknown): AuthUIConfig['pitch'] {
    if (!raw || typeof raw !== 'object') return undefined;
    const r = raw as Record<string, unknown>;
    const str = (v: unknown, max: number): string | undefined =>
        typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : undefined;
    const bullets = Array.isArray(r.bullets)
        ? r.bullets
            .map((b) => str(b, 200))
            .filter((b): b is string => !!b)
            .slice(0, 5)
        : undefined;
    const logoUrl = str(r.logoUrl, 300);
    const pitch = {
        title: str(r.title, 120),
        description: str(r.description, 600),
        bullets: bullets?.length ? bullets : undefined,
        // Consumer logo: https URLs only (rendered as a plain <img>).
        logoUrl: logoUrl?.startsWith('https://') ? logoUrl : undefined,
    };
    return (pitch.title || pitch.description || pitch.bullets || pitch.logoUrl) ? pitch : undefined;
}

function sanitiseApp(raw: unknown): AuthUIConfig['app'] {
    if (!raw || typeof raw !== 'object') return undefined;
    const r = raw as Record<string, unknown>;
    const logoUrl = typeof r.logoUrl === 'string' && r.logoUrl.startsWith('https://')
        ? r.logoUrl.slice(0, 300)
        : undefined;
    const displayName = typeof r.displayName === 'string' && r.displayName.trim()
        ? r.displayName.trim().slice(0, 60)
        : undefined;
    return (logoUrl || displayName) ? { logoUrl, displayName } : undefined;
}

const KNOWN_METHODS = ['wallet', 'passkey', 'social'] as const;
type KnownMethod = (typeof KNOWN_METHODS)[number];
/** The page's nonce for a link: what its server will look for in the ID token. */
function sanitiseLinkNonce(raw: unknown): string | undefined {
    const nonce = (raw as { nonce?: unknown } | null | undefined)?.nonce;
    if (typeof nonce !== 'string') return undefined;
    return /^[A-Za-z0-9._~-]{16,256}$/.test(nonce) ? nonce : undefined;
}

/** The user code of a device request: eight letters or digits, however typed. */
function sanitiseDeviceUserCode(raw: unknown): string | undefined {
    const code = (raw as { userCode?: unknown } | null | undefined)?.userCode;
    if (typeof code !== 'string') return undefined;
    const c = code.toUpperCase().replace(/[^A-Z0-9]/g, '');
    return c.length === 8 ? c : undefined;
}

/** A sign-in another device started and waits on (RFC 8628). */
interface DeviceRequest {
    sessionId: string;
    clientId: string;
    appName: string;
    rpId: string;
    brokerUrl?: string;
    /** The wallet link of the request, as the identity provider made it. */
    qrPayload: string;
    requestedAttributes?: string[];
}

/**
 * Reads a pending device request from the identity provider. Everything the
 * ceremony needs is in the wallet link the request was created with: the
 * request's own session, the app that asked and what it asked for.
 */
async function lookupDeviceRequest(idpBase: string, userCode: string): Promise<DeviceRequest> {
    const resp = await fetch(`${idpBase}/device/lookup?user_code=${encodeURIComponent(userCode)}`, { cache: 'no-store' });
    if (!resp.ok) throw new Error('This code is invalid or has expired');
    const data = await resp.json();
    if (data.status !== 'pending') throw new Error('This request has already been answered');
    const decoded = b64urlJson(new URL(String(data.qr_payload)).searchParams.get('p') ?? '');
    if (!decoded) throw new Error('This request cannot be approved here');
    const text = (v: unknown): string => (typeof v === 'string' ? v : '');
    const sessionId = text(decoded.sessionId);
    const clientId = text(decoded.clientId);
    if (!sessionId || !clientId) throw new Error('This request cannot be approved here');
    return {
        sessionId,
        clientId,
        appName: text(decoded.appName) || text(data.client_name) || clientId,
        rpId: text(decoded.rpId) || globalThis.location.hostname,
        ...(text(decoded.brokerUrl) ? { brokerUrl: text(decoded.brokerUrl) } : {}),
        qrPayload: String(data.qr_payload),
        ...(Array.isArray(decoded.requestedAttributes)
            ? { requestedAttributes: decoded.requestedAttributes.map(String) }
            : {}),
    };
}

/** An operation to approve, as the page passed it. */
interface OperationRequest {
    walletLink: string;
    passkey: boolean;
    /** Answers the operation's status: `approved`, `declined` or `gone`. */
    statusUrl: string;
    /** Declines the operation (POST, 204). */
    declineUrl: string;
    /** What the gate says when it ends each way. */
    messages: { approved: string; declined: string; expired: string };
}

/** The wallet links an operation approval may carry: the production wallet's
 *  scheme, or a dev or preview build's. */
const OPERATION_WALLET_LINK = /^privasys-wallet(-dev|-preview)?:\/\/[a-z-]+\?[A-Za-z0-9_=%&.-]+$/;

/** An address on this frame's own origin (the identity provider's), or nothing. */
function ownOriginUrl(raw: unknown): string | undefined {
    if (typeof raw !== 'string' || raw.length > 2048) return undefined;
    try {
        const u = new URL(raw, globalThis.location.origin);
        return u.origin === globalThis.location.origin ? u.href : undefined;
    } catch {
        return undefined;
    }
}

/** A line of the page's copy: plain text, capped. */
function sanitiseLine(raw: unknown, fallback: string): string {
    return typeof raw === 'string' && raw.trim() ? raw.trim().slice(0, 200) : fallback;
}

function sanitiseOperation(raw: unknown): OperationRequest | undefined {
    const o = raw as {
        walletLink?: unknown; passkey?: unknown; statusUrl?: unknown; declineUrl?: unknown;
        messages?: { approved?: unknown; declined?: unknown; expired?: unknown };
    } | null | undefined;
    if (!o || typeof o.walletLink !== 'string' || !OPERATION_WALLET_LINK.test(o.walletLink)) return undefined;
    const statusUrl = ownOriginUrl(o.statusUrl);
    const declineUrl = ownOriginUrl(o.declineUrl);
    if (!statusUrl || !declineUrl) return undefined;
    const m = o.messages ?? {};
    return {
        walletLink: o.walletLink,
        passkey: o.passkey === true,
        statusUrl,
        declineUrl,
        messages: {
            approved: sanitiseLine(m.approved, 'You can close this tab.'),
            declined: sanitiseLine(m.declined, 'You can close this tab.'),
            expired: sanitiseLine(m.expired, 'This approval has expired.'),
        },
    };
}

/** Waits until the operation's status says it is approved. */
async function waitOperation(op: OperationRequest, timeoutMs = 300_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const resp = await fetch(op.statusUrl, { cache: 'no-store' });
        const data = resp.ok ? await resp.json().catch(() => null) : null;
        if (data?.status === 'approved') return;
        if (data?.status === 'declined') throw new Error('The approval was declined.');
        if (data?.status === 'gone') throw new Error(op.messages.expired);
        await new Promise((r) => setTimeout(r, 1500));
    }
    throw new Error(op.messages.expired);
}

/** Waits until the identity provider says a session is authenticated. */
async function waitAuthenticated(pollUrl: string, timeoutMs = 120_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const resp = await fetch(pollUrl, { cache: 'no-store' });
        if (!resp.ok) throw new Error(`poll failed: ${resp.status}`);
        const data = await resp.json().catch(() => null);
        if (data?.authenticated) return;
        await new Promise((r) => setTimeout(r, 1500));
    }
    throw new Error('The request timed out');
}

/** The audience of the first access token: a resource name or `app:<app id>`. */
function sanitiseAudience(raw: unknown): string | undefined {
    if (typeof raw !== 'string') return undefined;
    return /^[A-Za-z0-9._:-]{1,253}$/.test(raw) ? raw : undefined;
}

// The adopter's list is an order as well as a filter (gate.ts), so it is
// kept as given, less anything unknown or repeated.
function sanitiseMethods(raw: unknown): AuthUIConfig['methods'] {
    if (!Array.isArray(raw)) return undefined;
    const out: KnownMethod[] = [];
    for (const m of raw) {
        if ((KNOWN_METHODS as readonly unknown[]).includes(m) && !out.includes(m as KnownMethod)) out.push(m as KnownMethod);
    }
    return out.length ? out : undefined;
}

// `providers` narrows the social list to a closed vocabulary; see providers.ts.

function sanitisePresentation(raw: unknown): AuthUIConfig['presentation'] {
    return raw === 'inline' || raw === 'page' || raw === 'modal' ? raw : undefined;
}

// ── Voucher push (one-tap wallet approval for an additional/changed app) ──
//
// Triggers a `voucher-only` wallet push via the broker and polls the IdP
// until a NEW EncAuth voucher for `appHost` lands. Throws with 'no-session',
// 'no-push', 'timeout' or a transport message. Shared by the parent-facing
// `privasys:voucher-request` RPC and the connect-mode approve flow.
async function requestVoucherPush(opts: {
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

async function generateSdkKeyPair(): Promise<{ keyPair: CryptoKeyPair; sdkPubB64: string }> {
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

// ── Session renewal (OIDC refresh_token) ────────────────────────────────
//
// Renewal coordination is client-side and cross-document. Several
// privasys.id iframes can be alive at once for the same session chain:
// the persistent renewal iframe, a sealed sign-in iframe kept mounted
// for session-relay, and one of each per additional tab. The IdP
// rotates refresh tokens with strict single-use semantics (the old
// token is deleted before the new one is issued), so exactly one
// document may run a refresh grant for a given session at a time. Every grant goes through refreshGrant, which holds a Web
// Locks API lock (origin-scoped across documents and tabs) for it.
//
// Renewal is scheduled from the access token's `exp` claim (not a flat
// delay), retries transient failures with backoff, and never removes
// the session unless the refresh-token chain is provably dead.

/** Renew when the token has less than this long to live. */
const RENEW_MARGIN_MS = 90_000;
/** Random spread so N documents don't fire at the same instant. */
const RENEW_JITTER_MS = 15_000;
/** Backoff schedule for transient renewal failures (network, IdP 5xx). */
const RENEW_RETRY_MS = [5_000, 30_000, 120_000];
/** Backstop cadence; no-ops unless the token is inside the margin. */
const RENEW_HEARTBEAT_MS = 60_000;

/**
 * How long the step-up approve gate waits for the holder to act on the
 * pushed attribute approval before falling back to the full ceremony.
 * Deliberately well inside the authorize session's 5-minute window so the
 * fallback ceremony still has time to complete on the same session.
 */
const STEP_UP_APPROVAL_WINDOW_MS = 90_000;

// Everything this document renews is kept per session key, so two clients
// sharing an rpId keep their own timers, retries and notifications. A timer
// outlives the message that armed it, so it holds its key.
const renewalTimers = new Map<string, ReturnType<typeof setTimeout>>();
const renewalRetryCount = new Map<string, number>();
/** Sessions this document renews, with the parent origin to notify. */
const renewalParents = new Map<string, { key: SessionKey; parentOrigin: string }>();
/** Last access token seen per session; dedupes storage-event notifications. */
const lastSeenTokens = new Map<string, string>();

function cancelRenewal(key: SessionKey): void {
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
async function withRefreshLock<T>(key: SessionKey, fn: () => Promise<T>): Promise<T> {
    const locks = (navigator as Navigator & { locks?: LockManager }).locks;
    if (locks?.request) {
        return locks.request(`privasys-refresh:${sessionKeyId(key)}`, fn) as Promise<T>;
    }
    return fn();
}

/** Epoch-ms `exp` of a JWT, or null when unreadable. */
function tokenExpMs(token: string): number | null {
    const exp = jwtPayload(token)?.exp;
    return typeof exp === 'number' ? exp * 1000 : null;
}

// What the identity provider said about a page and a client, for this
// document's life. Only a yes is kept: a refusal or a failed lookup is asked
// again, so registering an origin takes effect without a reload.
const pageVerdicts = new Set<string>();

/**
 * Whether the page at `pageOrigin` is one `clientId` registered: its
 * redirect URIs' origins and its allowed origins, the list a sign-in with no
 * redirect is checked against. The identity provider answers, logs a page it
 * does not know, and refuses it once that check is enforced. A lookup that
 * fails is a no: nothing else here works without the identity provider.
 */
async function pageIsClients(clientId: string, pageOrigin: string): Promise<boolean> {
    const key = `${clientId}|${pageOrigin}`;
    if (pageVerdicts.has(key)) return true;
    try {
        const u = new URL('/session/client-origin', globalThis.location.origin);
        u.searchParams.set('client_id', clientId);
        u.searchParams.set('origin', pageOrigin);
        const resp = await fetch(u.toString(), { cache: 'no-store' });
        if (!resp.ok) return false;
        const body = await resp.json().catch(() => null);
        if (body?.allowed !== true) return false;
        pageVerdicts.add(key);
        return true;
    } catch {
        return false;
    }
}

// ── The page's platform ──────────────────────────────────────────────────
//
// Every page under one registrable domain shares this frame's storage, and
// pages of more than one platform can live under one domain (a production
// platform and a test platform, say). The identity provider publishes which
// domains belong to which platform (platforms.ts places a page).

const PLATFORM_LIST_TTL_MS = 5 * 60_000;
let platformList: { at: number; list: PlatformEntry[] } | null = null;

/** The identity provider's platform list, or null when it cannot be read. */
async function loadPlatforms(): Promise<PlatformEntry[] | null> {
    if (platformList && Date.now() - platformList.at < PLATFORM_LIST_TTL_MS) return platformList.list;
    try {
        const resp = await fetch(new URL('/wallet/platforms', globalThis.location.origin).toString(), { cache: 'no-store' });
        if (resp.ok) {
            const list = parsePlatforms(await resp.json().catch(() => null));
            if (list) {
                platformList = { at: Date.now(), list };
                return list;
            }
        }
    } catch { /* unreadable: the last good list, if any */ }
    return platformList?.list ?? null;
}

/**
 * The session key a message names: the page's platform, from the origin the
 * browser reports for it and never from anything the page says, and the
 * rpId and client the message names. Null when the platform cannot be told
 * or the message names no client: such a message reaches no session.
 */
function messageKey(scope: PlatformScope | null, data: { rpId?: unknown; clientId?: unknown }): SessionKey | null {
    if (!scope) return null;
    if (typeof data.clientId !== 'string' || !data.clientId) return null;
    if (typeof data.rpId !== 'string' || !data.rpId) return null;
    return { platform: scope.platform, rpId: data.rpId, clientId: data.clientId };
}

/**
 * The stored session this page may use, or undefined. A session belongs to a
 * client, and only that client's own pages are given it: every page under one
 * registrable domain shares this frame's storage, so without this a page
 * could take another app's session by naming its rpId.
 */
async function sessionForPage(key: SessionKey | null, pageOrigin: string): Promise<AuthSession | undefined> {
    const session = key ? sessions.get(key) : undefined;
    if (!session) return undefined;
    return (await pageIsClients(key!.clientId, pageOrigin)) ? session : undefined;
}

// ── The device popup ─────────────────────────────────────────────────────
//
// A browser gives this frame a separate storage on every site that embeds
// it, so on a site the person has never signed in to, the frame cannot tell
// that their phone is already known. A window on this origin that is NOT
// embedded sees one storage, the same whichever site opened it. So the phone
// is remembered there, and read through a short popup of this same page
// (DEVICE_POPUP_HASH), opened inside the click on the wallet button.
//
// The popup announces itself to the windows of this origin in its opener; the
// frame that is waiting answers with what it wants (read, or store this
// phone), the popup does it and closes. Every message is posted to this
// origin only, so the embedding page takes no part and learns nothing.
const DEVICE_POPUP_HASH = '#device';
const DEVICE_POPUP_URL = `${globalThis.location.origin}/auth/${DEVICE_POPUP_HASH}`;
const DEVICE_POPUP_WAIT_MS = 5_000;
// Names of wallets the popup reported, kept so a wallet first used on this
// site is remembered here under the name it has everywhere else.
const deviceLabels = new Map<string, string>();

type DeviceAsk =
    | { op: 'read' }
    | { op: 'store'; pushToken: string; brokerUrl: string; label?: string }
    | { op: 'forget'; pushToken: string };
type KnownDevice = { pushToken: string; brokerUrl: string; label: string };

/** A remembered wallet as the gate shows it. */
function shown(d: DeviceHint): KnownDevice {
    return { pushToken: d.pushToken, brokerUrl: d.brokerUrl, label: deviceLabel(d) };
}

/**
 * Open the device popup and ask it one thing. `open` runs synchronously, so
 * a caller inside a click keeps the click's permission to open a window; it
 * resolves false when the popup could not open. Resolves the remembered
 * wallets for a read (none on any failure), and none for a store or a forget.
 */
function askDevicePopup(open: () => boolean | Promise<boolean>, ask: DeviceAsk): Promise<KnownDevice[]> {
    return new Promise((resolve) => {
        const own = globalThis.location.origin;
        const id = Math.random().toString(36).slice(2);
        let done = false;
        const finish = (v: KnownDevice[]) => {
            if (done) return;
            done = true;
            window.removeEventListener('message', onMessage);
            clearTimeout(timer);
            resolve(v);
        };
        const onMessage = (ev: MessageEvent) => {
            if (ev.origin !== own || !ev.source || ev.source === window.parent) return;
            const d = ev.data;
            if (d?.type === 'privasys:device:hello') {
                (ev.source as Window).postMessage({ type: 'privasys:device:ask', id, ...ask }, own);
            } else if (d?.type === 'privasys:device:answer' && d.id === id) {
                const list: unknown[] = Array.isArray(d.devices) ? d.devices : [];
                finish(list.slice(0, 8).flatMap((h) => {
                    const k = h as Partial<KnownDevice> | null;
                    return k && typeof k.pushToken === 'string' && k.pushToken
                        ? [{
                            pushToken: k.pushToken,
                            brokerUrl: typeof k.brokerUrl === 'string' ? k.brokerUrl : '',
                            label: typeof k.label === 'string' && k.label ? k.label.slice(0, 80) : 'Phone',
                        }]
                        : [];
                }));
            }
        };
        window.addEventListener('message', onMessage);
        const timer = setTimeout(() => finish([]), DEVICE_POPUP_WAIT_MS);
        Promise.resolve(open()).then((opened) => { if (!opened) finish([]); }, () => finish([]));
    });
}

/** Opened as the device popup: do what the waiting frame asks, then close. */
function runDevicePopup(): void {
    const own = globalThis.location.origin;
    window.addEventListener('message', (ev: MessageEvent) => {
        if (ev.origin !== own || !ev.source) return;
        const d = ev.data;
        if (d?.type !== 'privasys:device:ask' || typeof d.id !== 'string') return;
        let devices: KnownDevice[] = [];
        const token = typeof d.pushToken === 'string' && d.pushToken && d.pushToken.length <= 4096 ? d.pushToken : '';
        if (d.op === 'store') {
            if (token) {
                sessions.saveDeviceHint(token,
                    typeof d.brokerUrl === 'string' ? d.brokerUrl.slice(0, 512) : '',
                    cleanDeviceLabel(d.label));
            }
        } else if (d.op === 'forget') {
            if (token) sessions.forgetDevice(token);
        } else {
            devices = sessions.getDevices().map(shown);
        }
        (ev.source as Window).postMessage({ type: 'privasys:device:answer', id: d.id, devices }, own);
        window.close();
    });
    // The frame is the opener itself (a visible gate), or a frame inside it
    // (a headless page opened this window for its frame).
    const targets: Window[] = [];
    try {
        const opener = window.opener as Window | null;
        if (opener) {
            targets.push(opener);
            for (let i = 0; i < opener.length; i++) targets.push(opener[i] as unknown as Window);
        }
    } catch { /* an opener that cannot be walked: nothing to announce to */ }
    for (const t of targets) {
        try { t.postMessage({ type: 'privasys:device:hello' }, own); } catch { /* not ours */ }
    }
    // Nobody asked: do not leave an empty window behind.
    setTimeout(() => window.close(), DEVICE_POPUP_WAIT_MS);
}

/** Whether an access token carries the identity provider's wallet marker. */
function tokenSaysWallet(token: string): boolean {
    const w = jwtPayload(token)?.wallet;
    return w === true || w === 'true';
}

/** Whether an access token was issued for this audience. */
function tokenAudienceIs(token: string, audience: string): boolean {
    const aud = jwtPayload(token)?.aud;
    return Array.isArray(aud) ? aud.includes(audience) : aud === audience;
}

/** Check whether an access token's exp claim is within a safety margin. */
function isTokenExpired(token: string, marginMs = 30_000): boolean {
    const exp = tokenExpMs(token);
    if (exp === null) return false;
    return exp - marginMs < Date.now();
}

/** True when the token should be renewed now (inside the renewal margin). */
function needsRenewal(token: string): boolean {
    return isTokenExpired(token, RENEW_MARGIN_MS);
}

function scheduleRenewal(key: SessionKey, session: AuthSession, parentOrigin: string): void {
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

function scheduleRenewalRetry(key: SessionKey, parentOrigin: string): void {
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
type GrantResult =
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
async function refreshGrant(
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
async function renewSession(
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
async function renewIfNeeded(
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
const RENEW_NOW_MIN_MS = 10_000;
const renewalsNow = new Map<string, Promise<AuthSession | undefined>>();
const lastRenewNow = new Map<string, number>();

/**
 * Renew the session now, whatever its token's expiry: what the person may do
 * has changed (a role was granted, an account switched), and a renewal reads
 * it afresh. Within RENEW_NOW_MIN_MS of the last one, the renewal runs when
 * that time is up, so a page asking in a loop makes one grant per interval.
 *
 * Resolves with the renewed session, the unchanged one when the renewal
 * could not run (it is retried as usual), or undefined when the chain is dead.
 */
function renewNow(key: SessionKey, parentOrigin: string): Promise<AuthSession | undefined> {
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

// ── OIDC PKCE helpers ───────────────────────────────────────────────────

async function generatePKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    const codeVerifier = Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
    const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    return { codeVerifier, codeChallenge };
}

/** Poll the IdP session status until auth code is available or timeout. */
async function pollSessionStatus(pollUrl: string, timeoutMs = 120_000): Promise<string> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const resp = await fetch(pollUrl);
        if (!resp.ok) throw new Error(`poll failed: ${resp.status}`);
        const data = await resp.json();
        if (data.authenticated && data.redirect_uri) {
            const url = new URL(data.redirect_uri, globalThis.location.origin);
            const code = url.searchParams.get('code');
            if (code) return code;
        }
        await new Promise((r) => setTimeout(r, 1500));
    }
    throw new Error('OIDC session timed out');
}

/** Complete an OIDC session directly (after relay/social auth) and get the auth code. */
async function completeSession(
    idpBase: string,
    sessionId: string,
    attributes?: Record<string, string>,
): Promise<string> {
    const resp = await fetch(`${idpBase}/session/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            session_id: sessionId,
            user_id: attributes?.sub || '',
            attributes: attributes || {},
        }),
    });
    if (!resp.ok) {
        const body = await resp.json().catch(() => ({ error: resp.statusText }));
        throw new Error(body.error_description || body.error || `Session complete failed: ${resp.status}`);
    }
    const data = await resp.json();
    if (!data.code) throw new Error('No authorization code returned');
    return data.code;
}

/** Exchange an authorization code for tokens via the IdP /token endpoint. */
async function exchangeCode(
    idpBase: string,
    code: string,
    clientId: string,
    codeVerifier: string,
): Promise<{ access_token: string; id_token?: string; refresh_token?: string; expires_in: number }> {
    const resp = await fetch(`${idpBase}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            client_id: clientId,
            code_verifier: codeVerifier,
        }),
    });
    if (!resp.ok) {
        const body = await resp.json().catch(() => ({ error: resp.statusText }));
        throw new Error(body.error_description || body.error || `Token exchange failed: ${resp.status}`);
    }
    return resp.json();
}

// contentHeightReporter posts the rendered UI's height to the parent page,
// at most once per animation frame, so an inline embed can size its iframe
// to the content (frame-size.ts).
function contentHeightReporter(parentOrigin: string): (px: number) => void {
    let pending: number | null = null;
    return (px: number): void => {
        pending = px;
        const flush = (): void => {
            if (pending === null) return;
            const height = pending;
            pending = null;
            window.parent.postMessage({ type: FRAME_SIZE_MESSAGE, height }, parentOrigin);
        };
        if (typeof requestAnimationFrame === 'function') requestAnimationFrame(flush);
        else flush();
    };
}

/** The adopter's spend hint, reduced to a non-negative integer cap. */
function sanitiseSpend(v: unknown): { cap?: number } {
    if (!v || typeof v !== 'object') return {};
    const cap = (v as { cap?: unknown }).cap;
    if (typeof cap === 'number' && Number.isFinite(cap) && cap >= 0) {
        return { cap: Math.floor(cap) };
    }
    return {};
}

// ── Message handler ─────────────────────────────────────────────────────

// How a device sign-in or an operation approval can end without approval,
// with the gate staying on that outcome (AuthUI rejects with these codes).
const GATE_OUTCOMES = ['declined', 'decline-failed', 'approval-failed'] as const;
const isGateOutcome = (code: string): code is typeof GATE_OUTCOMES[number] =>
    (GATE_OUTCOMES as readonly string[]).includes(code);
const gateOutcomeResult = (code: string) =>
    ({ approved: false, outcome: code, sessionToken: '', method: 'wallet', sessionId: '' });

// The origin of the page this frame serves, fixed by its first message. A
// frame never changes pages without being reloaded.
let servedOrigin: string | null = null;

/**
 * Whether a message comes from the page this frame serves. Only that page may
 * drive the frame: any other window that can reach it (another frame on the
 * same page, through `parent.frames`) could otherwise act on the person's
 * session. The popups this frame opens answer on listeners of their own.
 */
function fromServedPage(e: MessageEvent): boolean {
    if (window.parent === window || e.source !== window.parent) return false;
    if (servedOrigin === null) servedOrigin = e.origin;
    return e.origin === servedOrigin;
}

window.addEventListener('message', async (e: MessageEvent) => {
    const data = e.data;
    if (!data || typeof data.type !== 'string' || !data.type.startsWith('privasys:')) return;
    if (!fromServedPage(e)) return;
    // The page's platform, from the origin the browser reports for it. A
    // platform that cannot be told matches no session.
    const list = await loadPlatforms();
    const pageScope = list ? platformScopeOf(list, e.origin) : null;
    // The session this message is about; an init names its client in its
    // config and builds its own below.
    const key = messageKey(pageScope, data);

    if (data.type === 'privasys:init') {
        const config: AuthUIConfig & {
            /** The page's API origin, recorded on the session. */
            apiBase?: string;
            clientId?: string;
            scope?: string | string[];
            sessionRelay?: { appHost: string; extraAppHosts?: string[] };
            spend?: { cap?: number };
            connect?: { mode?: string; reason?: string | null; added?: string[] };
            caps?: string[];
            billingGrant?: string;
            attributes?: readonly string[];
            /** Adopter theme and footer choice; sanitised below. */
            theme?: unknown;
            legal?: unknown;
            /** The audience of the first access token; sanitised below. */
            audience?: unknown;
            /** Adopter preference for the social providers; sanitised below. */
            providers?: unknown;
            /** The page draws its own gate; sanitised below. */
            headless?: unknown;
            /** Link a Privasys ID to a person signed in another way; sanitised below. */
            link?: unknown;
            /** Approve a sign-in another device started; sanitised below. */
            deviceRequest?: unknown;
            /** Approve an operation someone started; sanitised below. */
            operationApproval?: unknown;
        } = data.config;
        const parentOrigin = e.origin;
        // A link is a Privasys ID sign-in whose only result is an ID token
        // for the page's server: who the person is under this client, proven
        // for the page's own nonce. Nothing of the page's existing session is
        // read or replaced, and nothing but the wallet can answer it.
        if (config.link !== undefined && !sanitiseLinkNonce(config.link)) {
            window.parent.postMessage({ type: 'privasys:error', error: 'link needs a nonce of 16 to 256 URL-safe characters' }, parentOrigin);
            return;
        }
        const linkNonce = sanitiseLinkNonce(config.link);
        if (linkNonce) {
            config.methods = ['wallet'];
            config.scope = 'openid';
            delete config.sessionRelay;
            delete config.spend;
            delete config.connect;
            delete config.billingGrant;
            delete config.attributes;
            delete config.audience;
        }
        // Only the device and operation approvals below keep the gate open on
        // their outcome; a page cannot ask for it.
        delete config.finalScreen;
        delete config.decline;
        // A device request: the ceremony runs on the request the other device
        // created, for the app that asked, so the holder sees that app's
        // consent and the device gets what it asked for. Only the identity
        // provider's own pages may ask for this: the code is the capability,
        // and a foreign page must not be able to walk a visitor through
        // approving someone else's device.
        let device: DeviceRequest | null = null;
        if (config.deviceRequest !== undefined) {
            const userCode = sanitiseDeviceUserCode(config.deviceRequest);
            if (!userCode || linkNonce || parentOrigin !== globalThis.location.origin) {
                window.parent.postMessage({ type: 'privasys:error', error: 'a device request cannot be approved from this page' }, parentOrigin);
                return;
            }
            try {
                device = await lookupDeviceRequest(globalThis.location.origin, userCode);
            } catch (err) {
                window.parent.postMessage({ type: 'privasys:error', error: err instanceof Error ? err.message : 'This code is invalid or has expired' }, parentOrigin);
                return;
            }
            config.methods = ['wallet'];
            config.finalScreen = { title: 'Approved', message: 'Your device continues on its own. You can close this tab.' };
            config.decline = {
                label: 'Not me, deny',
                title: 'Request denied',
                message: 'You rejected this sign-in request. You can close this tab.',
                run: async () => {
                    const resp = await fetch(`${globalThis.location.origin}/device/deny`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ user_code: userCode }),
                    });
                    if (!resp.ok) throw new Error('this request is no longer open');
                },
            };
            config.clientId = device.clientId;
            config.appName = device.appName;
            config.rpId = device.rpId;
            if (device.brokerUrl) config.brokerUrl = device.brokerUrl;
            delete config.sessionRelay;
            delete config.spend;
            delete config.connect;
            delete config.billingGrant;
            delete config.attributes;
            delete config.audience;
        }
        // Every sign-in is for a client; only an operation approval, which
        // signs nobody in, has none.
        if (config.operationApproval === undefined && (typeof config.clientId !== 'string' || !config.clientId)) {
            window.parent.postMessage({ type: 'privasys:error', error: 'clientId is required' }, parentOrigin);
            return;
        }
        // A page gets its own platform's tokens and never another platform's.
        // Without the platform list there is no telling which is which, so
        // there is no sign-in.
        if (!pageScope) {
            window.parent.postMessage({ type: 'privasys:error', error: 'Sign-in is unavailable right now. Try again in a moment.' }, parentOrigin);
            return;
        }
        if (!device && !linkNonce) {
            const asked = sanitiseAudience(config.audience);
            if (asked && pageScope.platforms.includes(asked) && asked !== pageScope.platform) {
                window.parent.postMessage({ type: 'privasys:error', error: `audience ${asked} is not for a page on this platform` }, parentOrigin);
                return;
            }
            if (!asked && pageScope.platform !== pageScope.defaultPlatform) config.audience = pageScope.platform;
        }
        // The inline frame reports its content height so the embedding page
        // can size the iframe to it (frame-size.ts); throttled to a frame.
        const onContentHeight = contentHeightReporter(parentOrigin);

        // Wallet handoff via the parent page (mobile): only when the frame
        // client declared it handles `privasys:navigate` — older bundled
        // clients ignore unknown messages and the tap would go dead.
        const parentCaps = Array.isArray(config.caps) ? config.caps : [];
        const onNavigate = parentCaps.includes('parent-navigate')
            ? (url: string): void => {
                window.parent.postMessage({ type: 'privasys:navigate', url }, parentOrigin);
            }
            : undefined;
        // Headless: the page renders the gate itself from the options this
        // frame reports, and follows the flow through state reports. Only
        // a client that declared the capability gets the messages.
        const headless = config.headless === true && parentCaps.includes('headless');
        const onGateState = headless
            ? (s: GateState): void => {
                window.parent.postMessage({ type: 'privasys:gate:state', ...s }, parentOrigin);
            }
            : undefined;

        // Tear down any previous UI / session-relay handshake.
        if (activeUI) {
            activeUI.destroy();
            activeUI = null;
        }
        pendingHandshake = null;

        // Adopter-supplied UI config, strictly sanitised (rendered in this
        // trusted origin). Used by every AuthUI constructed below.
        const presentation = sanitisePresentation(config.presentation);
        const pitch = sanitisePitch(config.pitch);
        const app = sanitiseApp(config.app);
        const theme = sanitiseTheme(config.theme);
        const legal = config.legal === false ? false : undefined;
        // The adopter's explicit choice of methods; when absent, the
        // OIDC path below additionally filters methods by ATTRIBUTE
        // capability (a method that cannot deliver what the app marked
        // as essential is hidden). Signing in without the wallet is a
        // supported, deliberately degraded mode (no attestation
        // verification) — never blanket-blocked.
        const methods = sanitiseMethods(config.methods);
        // The adopter's preferred external identity providers, applied to
        // the list the IdP publishes once it has been fetched below.
        const providers = sanitiseProviders(config.providers);

        // An operation someone started elsewhere, to approve. Only the
        // identity provider's own pages may run it: the request is the
        // capability, and a foreign page must not walk a visitor through
        // approving someone else's operation.
        if (config.operationApproval !== undefined) {
            const operation = sanitiseOperation(config.operationApproval);
            if (!operation || linkNonce || device || parentOrigin !== globalThis.location.origin) {
                window.parent.postMessage({ type: 'privasys:error', error: 'this approval cannot be shown on this page' }, parentOrigin);
                return;
            }
            const operationUI = new AuthUI({
                onContentHeight,
                appName: config.appName,
                rpId: config.rpId || config.appName,
                presentation,
                app,
                pitch,
                theme,
                legal,
                onNavigate,
                finalScreen: { title: 'Approved', message: operation.messages.approved },
                decline: {
                    label: 'Not me, decline',
                    title: 'Declined',
                    message: operation.messages.declined,
                    run: async () => {
                        const resp = await fetch(operation.declineUrl, { method: 'POST' });
                        if (resp.status !== 204) throw new Error('this approval is no longer open');
                    },
                },
                operationApproval: {
                    walletLink: operation.walletLink,
                    ...(operation.passkey
                        ? { onPasskey: () => window.parent.postMessage({ type: 'privasys:operation:passkey' }, parentOrigin) }
                        : {}),
                    wait: () => waitOperation(operation),
                },
            });
            activeUI = operationUI;
            try {
                await operationUI.signIn();
                window.parent.postMessage(
                    { type: 'privasys:result', result: { approved: true, sessionToken: '', method: 'wallet', sessionId: '' } },
                    parentOrigin,
                );
            } catch (err) {
                const msg = err instanceof Error ? err.message : '';
                if (isGateOutcome(msg)) {
                    // The gate shows how it ended and stays on it.
                    window.parent.postMessage({ type: 'privasys:result', result: gateOutcomeResult(msg) }, parentOrigin);
                } else if (msg === 'Authentication cancelled' || msg === 'AuthUI destroyed') {
                    window.parent.postMessage({ type: 'privasys:cancel' }, parentOrigin);
                } else {
                    window.parent.postMessage({ type: 'privasys:error', error: msg || 'The approval was not completed' }, parentOrigin);
                }
            } finally {
                if (activeUI === operationUI) activeUI = null;
            }
            return;
        }
        // The session this sign-in is for.
        const rpId = config.rpId || config.appName;
        const initKey: SessionKey = { platform: pageScope.platform, rpId, clientId: config.clientId! };
        // Connect-mode approve: an existing wallet session whose sealed
        // voucher the enclave refused (measurement change) or that has no
        // voucher for this app yet. One-tap wallet push re-verification,
        // rendered by AuthUI. Falls through to the full ceremony when it
        // cannot complete (no wallet push, timeout, or the user chose
        // "Sign in another way").
        // It RE-USES the stored access token, so it must never serve a
        // widened attribute request: a widened set needs a freshly minted
        // token, which only the OIDC ceremony (and its step-up push path)
        // can produce.
        if (config.connect?.mode === 'approve' && config.sessionRelay?.appHost
            && config.connect.reason !== 'attributes-widened') {
            const appHost = config.sessionRelay.appHost;
            const session = sessions.get(initKey);
            if (session?.token && session.pushToken && session.brokerUrl) {
                const appLabel = (config.appName || rpId)
                    .replace(/[-_]/g, ' ')
                    .replace(/\b\w/g, (c) => c.toUpperCase());
                const approveUI = new AuthUI({
                    onContentHeight,
                    appName: config.appName,
                    rpId,
                    presentation,
                    app,
                    pitch,
                    theme,
                    legal,
                    headless,
                    onGateState,
                    approveFlow: {
                        appLabel,
                        reason: config.connect.reason ?? null,
                        run: async () => {
                            await requestVoucherPush({
                                key: initKey,
                                appName: config.appName,
                                appHost,
                            });
                            // Resume the sealed session from the fresh
                            // voucher and adopt it as this iframe's active
                            // sealed transport.
                            const getEncAuth = makeGetEncAuth(initKey, appHost);
                            const result = await PrivasysSession.resume({ host: appHost, getEncAuth });
                            if ('error' in result) {
                                throw new Error(result.reason
                                    ? `${result.error}:${result.reason}`
                                    : String(result.error));
                            }
                            adoptSession(appHost, result.session, 0, parentOrigin);
                        },
                    },
                });
                activeUI = approveUI;
                try {
                    await approveUI.signIn();
                    // Sealed transport now lives in THIS iframe; hand the
                    // parent the proxy handle and the result (existing token).
                    window.parent.postMessage({
                        type: 'privasys:session:ready',
                        sessionId: activeSession!.sessionId,
                        appHost,
                        expiresAt: 0,
                    }, parentOrigin);
                    const result: SignInResult = {
                        sessionToken: session.token,
                        method: 'wallet',
                        sessionId: activeSession!.sessionId,
                        sessionRelay: {
                            sessionId: activeSession!.sessionId,
                            encPub: '',
                            expiresAt: 0,
                        },
                    };
                    window.parent.postMessage({
                        type: 'privasys:result',
                        result: { ...result, accessToken: session.token },
                    }, parentOrigin);
                    activeUI = null;
                    return;
                } catch (err) {
                    activeUI = null;
                    const msg = err instanceof Error ? err.message : '';
                    if (msg === 'Authentication cancelled' || msg === 'AuthUI destroyed') {
                        window.parent.postMessage({ type: 'privasys:cancel' }, parentOrigin);
                        return;
                    }
                    // 'approve-fallback' or a hard failure — run the full
                    // ceremony below in this same iframe.
                }
            }
            // No wallet-push-capable session → full ceremony below.
        }

        // If the parent opted into session-relay, generate the SDK keypair
        // up-front and hand the public half to the AuthUI so the QR / push
        // request asks the wallet to bootstrap a sealed session against the
        // enclave during the FIDO2 ceremony. The private key never leaves
        // this iframe.
        let sessionRelayUI: AuthUIConfig['sessionRelay'] | undefined;
        if (config.sessionRelay?.appHost) {
            const { keyPair, sdkPubB64 } = await generateSdkKeyPair();
            pendingHandshake = {
                appHost: config.sessionRelay.appHost,
                key: initKey,
                sdkKeyPair: keyPair,
                sdkPubB64,
            };
            sessionRelayUI = {
                sdkPub: sdkPubB64,
                appHost: config.sessionRelay.appHost,
                ...(config.sessionRelay.extraAppHosts?.length
                    ? { extraAppHosts: config.sessionRelay.extraAppHosts }
                    : {}),
                // Spend consent rides the attested sign-in: the wallet knows
                // the app's attested identity (OID 3.6) only on this path.
                ...(config.spend ? { spend: sanitiseSpend(config.spend) } : {}),
            };
        }

        // IdP base URL (same origin as this iframe).
        const idpBase = globalThis.location.origin;
        const clientId = config.clientId!;

        // Create an OIDC session, authenticate, exchange the code for tokens.
        try {
            // 1. Generate PKCE code_verifier + code_challenge.
            const { codeVerifier, codeChallenge } = await generatePKCE();

            // 2. Create OIDC session via JSON authorize.
            const authorizeUrl = new URL('/authorize', idpBase);
            authorizeUrl.searchParams.set('client_id', clientId);
            authorizeUrl.searchParams.set('response_type', 'code');
            authorizeUrl.searchParams.set('code_challenge', codeChallenge);
            authorizeUrl.searchParams.set('code_challenge_method', 'S256');
            const scopeStr = Array.isArray(config.scope) ? config.scope.join(' ') : (config.scope || 'openid offline_access');
            // The first token is the only one the identity provider can
            // put the person's profile in (it keeps none to renew from),
            // so a page that needs an audience token asks for it here
            // rather than minting one by refresh after the sign-in.
            const audience = sanitiseAudience(config.audience);
            authorizeUrl.searchParams.set('scope', audience ? `audience:${audience} ${scopeStr}` : scopeStr);
            authorizeUrl.searchParams.set('response_mode', 'json');
            // The page this frame is in, as the browser reported it: the
            // result of this sign-in goes to that page, so the identity
            // provider checks the client registered it.
            authorizeUrl.searchParams.set('parent_origin', parentOrigin);
            if (linkNonce) authorizeUrl.searchParams.set('nonce', linkNonce);
            // A billing grant redirects the cost of any paid attribute
            // disclosure from this app's owner to the user who issued the
            // grant, so the person requiring the proof pays for it. Opaque
            // here: its issuer owns its scope, ceiling and single use.
            if (config.billingGrant) {
                authorizeUrl.searchParams.set('billing_grant', config.billingGrant);
            }
            // Attributes named one by one, alongside the scope. A scope is a
            // coarse bundle and cannot reach a government-backed `_id` key at
            // all, so for those this is the request.
            if (config.attributes?.length) {
                authorizeUrl.searchParams.set('attributes', config.attributes.join(' '));
            }
            // An existing session identifies the holder without a scan, so
            // the IdP can push the DELTA of a widened request to their
            // wallet for one-tap approval instead of forcing a full QR
            // ceremony. The hint only says who to push to — it authorises
            // nothing; everything the holder grants still flows through
            // the wallet's own verification. Withheld for session-relay
            // apps: their sealed binding needs the full wallet ceremony,
            // so a push approval would ring the holder's phone for a flow
            // the browser cannot use.
            const priorSession = sessions.get(initKey);
            const stepUpEligible = !linkNonce && !device && !!(priorSession?.token
                && priorSession.clientId === clientId
                && !isTokenExpired(priorSession.token)
                && !config.sessionRelay?.appHost);
            if (stepUpEligible) {
                authorizeUrl.searchParams.set('session_hint', priorSession!.token);
            }
            const authorize = async () => {
                const authResp = await fetch(authorizeUrl.toString(), {
                    headers: { Accept: 'application/json' },
                });
                if (!authResp.ok) {
                    const body = await authResp.json().catch(() => ({ error: authResp.statusText }));
                    const err = new Error(body.error_description || body.error || `Authorize failed: ${authResp.status}`);
                    // Preserve the OAuth error code (e.g. `insufficient_credits`
                    // on 402) so the parent can raise a typed error.
                    (err as Error & { code?: string }).code = body.error;
                    throw err;
                }
                return authResp.json();
            };
            // A device request already has its session at the identity
            // provider: the ceremony runs on that one, and no new request
            // is made.
            const authData = device
                ? {
                    session_id: device.sessionId,
                    poll_url: `${idpBase}/session/status?session_id=${encodeURIComponent(device.sessionId)}`,
                    qr_payload: device.qrPayload,
                    requested_attributes: device.requestedAttributes,
                }
                : await authorize();
            // The IdP keeps from the wallet any attribute the client's
            // registration does not allow. Signing in anyway would hand
            // the page a token without what it asked for, and the holder
            // an approval that showed less than the page expects, so the
            // sign-in fails and names the keys.
            const dropped: unknown = authData.dropped_attributes;
            if (Array.isArray(dropped) && dropped.length > 0) {
                const err = new Error(
                    `This app may not ask for ${dropped.join(', ')}: its registration does not allow ${dropped.length === 1 ? 'it' : 'them'}`,
                );
                (err as Error & { code?: string; dropped?: string[] }).code = 'attributes_not_allowed';
                (err as Error & { code?: string; dropped?: string[] }).dropped = dropped.map(String);
                throw err;
            }
            const oidcSessionId: string = authData.session_id;
            const pollUrl: string = authData.poll_url;
            const requestedAttributes: string[] | undefined = authData.requested_attributes;

            // The authorize response embeds the full wallet payload —
            // including per-attribute assurance requirements and any
            // paid-disclosure vouchers minted for gov attributes — in
            // the universal-link's `p=` parameter. Decode it and thread
            // those fields into the AuthUI so the relay descriptor / push
            // carries them; without them the wallet treats every attr as
            // 'any' assurance and gov disclosure never happens on the
            // iframe path.
            let attributeRequirements: AuthUIConfig['attributeRequirements'];
            let disclosureVouchers: AuthUIConfig['disclosureVouchers'];
            try {
                const decoded = b64urlJson(new URL(authData.qr_payload).searchParams.get('p') ?? '');
                attributeRequirements = decoded?.attributeRequirements as AuthUIConfig['attributeRequirements'];
                disclosureVouchers = decoded?.disclosureVouchers as AuthUIConfig['disclosureVouchers'];
            } catch { /* no wallet payload to thread */ }

            // Step-up push: the IdP resolved the session hint, found this
            // request WIDER than what that session's holder last granted,
            // and pushed the delta to their wallet. Render the one-tap
            // approve gate and poll for completion. "Sign in another way"
            // or an unanswered push falls back to the full ceremony below
            // on the SAME authorize session — the unused push approval is
            // single-use, session-bound, and dies with the session.
            let code: string | null = null;
            let uiResult: SignInResult | null = null;
            const deviceTrusted = !!sessions.getDeviceHint();
            const stepUp = (stepUpEligible ? authData.step_up : null) as
                { pushed?: boolean; added?: string[] } | null | undefined;
            if (stepUp?.pushed) {
                const rpIdHint = config.rpId || config.appName;
                const appLabel = (config.appName || rpIdHint)
                    .replace(/[-_]/g, ' ')
                    .replace(/\b\w/g, (c) => c.toUpperCase());
                const approveUI = new AuthUI({
                    onContentHeight,
                    appName: config.appName,
                    rpId: rpIdHint,
                    presentation,
                    app,
                    pitch,
                    theme,
                    legal,
                    headless,
                    onGateState,
                    approveFlow: {
                        appLabel,
                        reason: 'attributes-widened',
                        added: Array.isArray(stepUp.added) ? stepUp.added.map(String) : [],
                        run: async () => {
                            try {
                                code = await pollSessionStatus(pollUrl, STEP_UP_APPROVAL_WINDOW_MS);
                            } catch {
                                // Push not acted on in time (notifications
                                // off, phone out of reach) — fall back to
                                // the ceremony while the authorize session
                                // still has most of its window left.
                                throw new Error('approve-fallback');
                            }
                        },
                    },
                });
                activeUI = approveUI;
                try {
                    await approveUI.signIn();
                } catch (err) {
                    const msg = err instanceof Error ? err.message : '';
                    if (msg === 'Authentication cancelled' || msg === 'AuthUI destroyed') {
                        window.parent.postMessage({ type: 'privasys:cancel' }, parentOrigin);
                        return;
                    }
                    code = null; // 'approve-fallback' → full ceremony below
                } finally {
                    if (activeUI === approveUI) activeUI = null;
                }
            }

            if (code === null) {
            // Attribute-capability filtering (only when the adopter did
            // not choose methods explicitly): hide methods that cannot
            // deliver what the app marked as ESSENTIAL.
            //   - Passkey provides no attributes at all — hidden when
            //     anything is essential (e.g. a share link requiring a
            //     verified email).
            //   - Social can deliver provider-verified standard
            //     attributes (email, name) but not gov-assurance
            //     disclosures — hidden only when an essential attribute
            //     needs 'gov' (wallet-only by design).
            //   - The wallet delivers everything.
            // With no essential attributes every method stays, including
            // the passkey-then-verify-profile flow further below.
            let effectiveMethods = methods;
            if (!effectiveMethods && attributeRequirements) {
                const essential = Object.values(attributeRequirements)
                    .filter((r) => r?.essential);
                if (essential.some((r) => r.assurance === 'gov')) {
                    effectiveMethods = ['wallet'];
                } else if (essential.length > 0) {
                    effectiveMethods = ['wallet', 'social'];
                }
            }

            // 3. Fetch available social providers (skipped entirely when
            //    the effective methods exclude social sign-in).
            let socialProviders: string[] = [];
            let socialDisplayNames: Record<string, string> | undefined;
            let socialIcons: Record<string, string> | undefined;
            let socialOwn: OwnRegistration[] | undefined;
            if (!effectiveMethods || effectiveMethods.includes('social')) {
                try {
                    // Named for the client, the identity provider lists only
                    // the providers that client's users may sign in with.
                    const provQuery = config.clientId ? `?client_id=${encodeURIComponent(config.clientId)}` : '';
                    const provResp = await fetch(`${idpBase}/auth/social/providers${provQuery}`);
                    if (provResp.ok) {
                        const provData = await provResp.json();
                        const published: string[] = provData.providers ?? [];
                        // A preference that matches nothing yields the published
                        // list (selectProviders): a gate with no button at all
                        // would strand the user. Say so, since this console is
                        // the frame's, not the adopter's.
                        socialProviders = selectProviders(published, providers);
                        socialDisplayNames = sanitiseDisplayNames(provData.display_names);
                        socialIcons = sanitiseIcons(provData.icons);
                        socialOwn = sanitiseOwn(provData.own);
                        if (providers && !providers.some((p) => published.includes(p))) {
                            console.warn(
                                '[privasys] none of the requested providers',
                                providers, 'is configured at the identity provider; offering', published,
                            );
                        }
                    }
                } catch { /* social not available, that's fine */ }
            }

            // 4. Launch AuthUI with the OIDC session_id so QR/passkey link
            //    to the OIDC session; passkey calls go to the IdP's FIDO2 API.
            const pushToken = sessions.findPushToken();

            // Social auth handler: opens a popup to the IdP's social redirect,
            // then waits for the callback page to postMessage back.
            const openSocialPopup = (provider: string, own?: boolean, chooseAccount?: boolean): Promise<void> => {
                return new Promise<void>((resolve, reject) => {
                    const w = 500, h = 650;
                    const left = window.screenX + (window.innerWidth - w) / 2;
                    const top = window.screenY + (window.innerHeight - h) / 2;
                    // registration=own: the client's own registration, pressed as a button of its own.
                    const popupUrl = `${idpBase}/auth/social?provider=${encodeURIComponent(provider)}&session_id=${encodeURIComponent(oidcSessionId)}${own ? '&registration=own' : ''}${chooseAccount ? '&account=choose' : ''}`;
                    const popup = window.open(popupUrl, 'privasys-social', `width=${w},height=${h},left=${left},top=${top}`);

                    if (!popup) {
                        reject(new Error('Popup blocked — please allow popups for this site'));
                        return;
                    }

                    const cleanup = () => {
                        window.removeEventListener('message', onMessage);
                        clearInterval(pollClosed);
                    };

                    const onMessage = (ev: MessageEvent) => {
                        if (ev.source !== popup) return;
                        if (ev.data?.type === 'privasys:social-complete') {
                            cleanup();
                            popup.close();
                            resolve();
                        } else if (ev.data?.type === 'privasys:social-error') {
                            cleanup();
                            popup.close();
                            reject(new Error(ev.data.error || 'Social authentication failed'));
                        }
                    };

                    window.addEventListener('message', onMessage);

                    // Detect if user closes the popup manually.
                    const pollClosed = setInterval(() => {
                        if (popup.closed) {
                            cleanup();
                            reject(new Error('Authentication cancelled'));
                        }
                    }, 500);
                });
            };
            // Headless: a popup needs the click's activation, which the
            // page has and this frame does not, so the page opens it at
            // the address this frame names and reports how it ended.
            const popupViaParent = (provider: string, own?: boolean, chooseAccount?: boolean): Promise<void> => {
                return new Promise<void>((resolve, reject) => {
                    const id = Math.random().toString(36).slice(2);
                    const url = `${idpBase}/auth/social?provider=${encodeURIComponent(provider)}&session_id=${encodeURIComponent(oidcSessionId)}${own ? '&registration=own' : ''}${chooseAccount ? '&account=choose' : ''}`;
                    const onMessage = (ev: MessageEvent) => {
                        if (ev.source !== window.parent || ev.origin !== parentOrigin) return;
                        if (ev.data?.type !== 'privasys:gate:popup-result' || ev.data.id !== id) return;
                        window.removeEventListener('message', onMessage);
                        if (ev.data.ok === true) resolve();
                        else reject(new Error(String(ev.data.error || 'Authentication cancelled')));
                    };
                    window.addEventListener('message', onMessage);
                    window.parent.postMessage({ type: 'privasys:gate:popup', id, url }, parentOrigin);
                });
            };
            const onSocialAuth = headless ? popupViaParent : openSocialPopup;
            // The device popup: this frame opens it inside the click; a
            // headless page opens it for the frame, as it does a social one.
            const openDevicePopup = (): boolean | Promise<boolean> => {
                if (!headless) {
                    const w = 420, h = 240;
                    const left = window.screenX + (window.innerWidth - w) / 2;
                    const top = window.screenY + (window.innerHeight - h) / 2;
                    return !!window.open(DEVICE_POPUP_URL, 'privasys-device', `width=${w},height=${h},left=${left},top=${top}`);
                }
                return new Promise<boolean>((resolve) => {
                    const id = Math.random().toString(36).slice(2);
                    const onResult = (ev: MessageEvent) => {
                        if (ev.source !== window.parent || ev.origin !== parentOrigin) return;
                        if (ev.data?.type !== 'privasys:gate:popup-result' || ev.data.id !== id) return;
                        window.removeEventListener('message', onResult);
                        resolve(ev.data.ok === true);
                    };
                    window.addEventListener('message', onResult);
                    window.parent.postMessage({ type: 'privasys:gate:popup', id, url: DEVICE_POPUP_URL }, parentOrigin);
                });
            };

            activeUI = new AuthUI({
                ...config,
                onContentHeight,
                sessionId: oidcSessionId,
                fido2Base: `${idpBase}/fido2`,
                pushToken,
                deviceTrusted,
                socialProviders,
                socialDisplayNames,
                socialIcons,
                socialOwn,
                onSocialAuth,
                devices: sessions.getDevices().map(shown),
                lookupDevice: async () => {
                    const found = await askDevicePopup(openDevicePopup, { op: 'read' });
                    for (const d of found) deviceLabels.set(d.pushToken, d.label);
                    return found;
                },
                forgetDevice: async (token: string) => {
                    sessions.forgetDevice(token);
                    await askDevicePopup(openDevicePopup, { op: 'forget', pushToken: token });
                },
                rememberDevice: async (token: string, label?: string) => {
                    await askDevicePopup(openDevicePopup, { op: 'store', pushToken: token, brokerUrl: config.brokerUrl || '', ...(label ? { label } : {}) });
                },
                // A passkey carries no name or email; the gate asks for
                // them through a provider when the client wants them.
                profileAfterPasskey: !!requestedAttributes?.some(
                    (a: string) => a === 'email' || a === 'name',
                ),
                headless,
                onGateState,
                requestedAttributes,
                attributeRequirements,
                disclosureVouchers,
                sessionRelay: sessionRelayUI,
                // Same-device recovery: the AuthUI polls this while a
                // wallet flow is pending, so the ceremony completes
                // from IdP state when the broker relay died during the
                // app switch (page backgrounded → WS gone → the
                // wallet's relay message lands in the void).
                checkComplete: async () => {
                    const r = await fetch(pollUrl, { cache: 'no-store' });
                    if (!r.ok) return false;
                    const d = await r.json().catch(() => null);
                    return !!(d && d.authenticated);
                },
                // Sanitised copies override the raw postMessage values.
                presentation,
                app,
                pitch,
                theme,
                legal,
                methods: effectiveMethods,
                onNavigate,
                approveFlow: undefined,
            });

            if (headless) {
                window.parent.postMessage({ type: 'privasys:gate', options: activeUI.gateOptions() }, parentOrigin);
            }
            uiResult = await activeUI.signIn();

            // 5. Get the auth code:
            //    - Passkey: the IdP's FIDO2 handler already marked the session
            //      complete, so poll for it. If the relying party requested
            //      profile attributes (email/name), open a social login to
            //      source them — the social callback patches them onto the
            //      existing auth code.
            //    - Wallet (relay): call /session/complete to bridge.
            //    - Social: the popup callback already marked it complete, so
            //      call /session/complete to get the code (it's idempotent).
            if (device) {
                // The wallet answered over the relay: hand what it shared
                // to the identity provider, which completes the request.
                // A wallet that answered the identity provider directly
                // has completed it already.
                if (!uiResult.completedViaPoll) {
                    await completeSession(idpBase, oidcSessionId, uiResult.attributes);
                }
                await waitAuthenticated(pollUrl);
                code = '';
            } else if (uiResult.method === 'passkey') {
                // A client that asked for the name or email had the gate
                // confirm them with a provider after the passkey
                // (profileAfterPasskey); the provider's callback added
                // them to this session.
                code = await pollSessionStatus(pollUrl);
            } else if (uiResult.completedViaPoll) {
                // Same-device wallet flow: the relay died during the app
                // switch, the ceremony completed via the IdP status
                // poll. The wallet already linked the FIDO2 assertion
                // and patched attributes onto the auth code server-side.
                code = await pollSessionStatus(pollUrl);
            } else {
                // Wallet: pass profile from relay. Social: auth code
                // already exists with profile (the popup callback created it).
                code = await completeSession(
                    idpBase,
                    oidcSessionId,
                    uiResult.attributes,
                );
            }
            } // end full ceremony (skipped when the step-up push completed)

            // 5. Exchange code for JWT tokens.
            // A device request is approved now. Its tokens go to the device
            // that asked, which redeems them itself: this page gets none.
            if (device) {
                if (uiResult?.pushToken && config.brokerUrl && (uiResult.trustDevice || deviceTrusted)) {
                    sessions.saveDeviceHint(uiResult.pushToken, config.brokerUrl,
                        uiResult.deviceLabel ?? deviceLabels.get(uiResult.pushToken));
                }
                window.parent.postMessage(
                    { type: 'privasys:result', result: { approved: true, sessionToken: '', method: 'wallet', sessionId: oidcSessionId } },
                    parentOrigin,
                );
                return;
            }
            const tokens = await exchangeCode(idpBase, code, clientId, codeVerifier);

            // A link ends here. The page gets the ID token and nothing
            // else: no session is kept, so the one the person already
            // has for this client stands, and the access token of the
            // linked identity never leaves this frame.
            if (linkNonce) {
                if (!tokens.id_token) throw new Error('The identity provider returned no ID token');
                if (uiResult?.pushToken && config.brokerUrl && (uiResult.trustDevice || deviceTrusted)) {
                    sessions.saveDeviceHint(uiResult.pushToken, config.brokerUrl,
                        uiResult.deviceLabel ?? deviceLabels.get(uiResult.pushToken));
                }
                window.parent.postMessage(
                    { type: 'privasys:result', result: { linked: true, idToken: tokens.id_token, method: 'wallet', sessionId: oidcSessionId } },
                    parentOrigin,
                );
                return;
            }

            // 6. Store session with JWT access_token and refresh_token.
            // `requestedAttributes`/`scope` record the RAW request this
            // session was minted for; connect() compares future configs
            // against them to detect a widened request. A step-up push
            // completion has no ceremony result, so the wallet push
            // binding carries over from the prior session.
            const session: AuthSession = {
                token: tokens.access_token,
                rpId,
                origin: config.apiBase ?? '',
                authenticatedAt: Date.now(),
                pushToken: uiResult?.pushToken ?? priorSession?.pushToken,
                // The marker, or a ceremony that brought the wallet's
                // sealed binding, so a wallet user is never taken for
                // someone without one.
                wallet: tokenSaysWallet(tokens.access_token)
                    || !!uiResult?.sessionRelay || !!uiResult?.completedViaPoll,
                brokerUrl: config.brokerUrl || priorSession?.brokerUrl || '',
                refreshToken: tokens.refresh_token,
                clientId,
                requestedAttributes: [...(config.attributes ?? [])],
                scope: scopeStr,
            };
            sessions.store(initKey, session);
            if (session.pushToken && session.brokerUrl) {
                if (uiResult?.trustDevice || deviceTrusted) {
                    // A wallet found through the popup keeps the name it has there.
                    // The wallet's own name for the phone wins: it is current.
                    sessions.saveDeviceHint(session.pushToken, session.brokerUrl,
                        uiResult?.deviceLabel ?? deviceLabels.get(session.pushToken));
                }
            }
            scheduleRenewal(initKey, session, parentOrigin);

            // Install the sealed session so the parent's `frame.session()`
            // RPC works once the auth result lands.
            //
            // The session the app gets is established from the wallet's
            // EncAuth voucher, never from the wallet's own bootstrap: only
            // a voucher-backed bootstrap carries the caller's identity
            // (X-Privasys-Sub), and an app that attributes callers answers
            // an anonymous session 401 right after a successful sign-in.
            // The wallet uploads the voucher before relaying the result;
            // the bounded wait covers an older wallet that uploads after,
            // and the same-device flow, where the tab is backgrounded
            // during the app switch and the upload lands on the way back.
            const wantsSealed = !!config.sessionRelay?.appHost
                && (!!uiResult?.sessionRelay || !!uiResult?.completedViaPoll);
            if (wantsSealed && uiResult) {
                const appHost = config.sessionRelay!.appHost;
                const session = await resumeVoucherSession(
                    appHost,
                    initKey,
                    uiResult.completedViaPoll ? SAME_DEVICE_VOUCHER_WINDOW_MS : CEREMONY_VOUCHER_WINDOW_MS,
                );
                if (session) {
                    pendingHandshake = null;
                    adoptSession(appHost, session, 0, parentOrigin);
                    uiResult.sessionRelay = { sessionId: session.sessionId, encPub: '', expiresAt: 0 };
                    window.parent.postMessage({
                        type: 'privasys:session:ready',
                        sessionId: session.sessionId,
                        appHost,
                        expiresAt: 0,
                    }, parentOrigin);
                } else if (uiResult.sessionRelay) {
                    // No voucher landed in time. Fall back to the wallet's
                    // bootstrap so the app still gets a sealed channel,
                    // anonymous to the app until the voucher lands: the
                    // session keeps looking for it, and an app's 401
                    // makes it look at once (PrivasysSession.identify).
                    console.warn('[frame-host] no EncAuth voucher after the ceremony; installing the anonymous session');
                    await installSessionRelay(uiResult.sessionRelay, parentOrigin);
                }
            }

            // 7. Send result to parent with the access_token. A step-up
            // push completion has no ceremony result — synthesise the
            // wallet-shaped minimum (the parent reads accessToken).
            const baseResult: SignInResult = uiResult ?? {
                sessionToken: tokens.access_token,
                method: 'wallet',
                sessionId: oidcSessionId,
            };
            window.parent.postMessage(
                {
                    type: 'privasys:result',
                    result: {
                        ...baseResult,
                        accessToken: tokens.access_token,
                    },
                },
                parentOrigin,
            );
        } catch (err) {
            const msg = err instanceof Error ? err.message : 'Authentication failed';
            if (isGateOutcome(msg)) {
                // The gate shows how it ended and stays on it.
                window.parent.postMessage({ type: 'privasys:result', result: gateOutcomeResult(msg) }, parentOrigin);
            } else if (msg === 'Authentication cancelled' || msg === 'AuthUI destroyed') {
                window.parent.postMessage({ type: 'privasys:cancel' }, parentOrigin);
            } else {
                const errorCode = err instanceof Error
                    ? (err as Error & { code?: string }).code
                    : undefined;
                window.parent.postMessage(
                    { type: 'privasys:error', error: msg, ...(errorCode ? { errorCode } : {}) },
                    parentOrigin,
                );
            }
        } finally {
            activeUI = null;
        }
        return;
    }

    // A headless page's choice: only the embedding page may make it, and
    // the gate itself checks it against what it offers.
    if (data.type === 'privasys:gate:start') {
        const choice = sanitiseChoice(data.choice);
        if (choice && activeUI) activeUI.start(choice);
        return;
    }

    if (data.type === 'privasys:check-session') {
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
    if (data.type === 'privasys:renew-session') {
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

    if (data.type === 'privasys:clear-session') {
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
    if (data.type === 'privasys:get-token-for-audience') {
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

    // Incremental multi-app attestation: ask the wallet — via push — to
    // voucher an ADDITIONAL enclave host for the live session, then wait
    // for the (new) voucher to appear at the IdP. One biometric approval
    // on the phone; no WebAuthn ceremony, no sign-out. The parent then
    // resumes the sealed session for that host as usual.
    if (data.type === 'privasys:voucher-request') {
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
    if (data.type === 'privasys:session:request') {
        const id = data.id;
        const reply = (payload: Record<string, unknown>) =>
            window.parent.postMessage({ type: 'privasys:session:response', id, ...payload }, e.origin);
        if (!activeSession) {
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
            const resp = await activeSession.session.request(method, path, body, init);
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
    if (data.type === 'privasys:session:resume') {
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
        if (activeSession && activeSession.appHost === appHost) {
            reply({ sessionId: activeSession.sessionId, appHost, expiresAt: activeSession.expiresAt });
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
    if (data.type === 'privasys:session:stream-cancel') {
        const id = String(data.id ?? '');
        const reader = streamReaders.get(id);
        if (reader) void reader.cancel().catch(() => undefined);
        else if (id && cancelledStreams.size < 64) cancelledStreams.add(id);
        return;
    }

    if (data.type === 'privasys:session:stream-request') {
        const id = data.id;
        const post = (type: string, payload: Record<string, unknown> = {}) =>
            window.parent.postMessage({ type, id, ...payload }, e.origin);
        if (!activeSession) {
            post('privasys:session:stream-error', { error: 'no active session' });
            return;
        }
        try {
            const method = String(data.method || 'POST').toUpperCase();
            const path = String(data.path || '/');
            const body = data.body as unknown;
            const init = (data.init as RequestInit | undefined) ?? undefined;
            const resp = await activeSession.session.stream(method, path, body, init);
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
    if (data.type === 'privasys:session:ws-open') {
        const id = data.id as number;
        const post = (type: string, payload: Record<string, unknown> = {}) =>
            window.parent.postMessage({ type, id, ...payload }, e.origin);
        if (!activeSession) {
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
            ws = activeSession.session.openWebSocket(String(data.path || '/'));
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
    if (data.type === 'privasys:session:ws-send') {
        const ws = activeWebSockets.get(data.id as number);
        if (ws) {
            try { ws.send(data.data as Uint8Array); } catch { /* closed mid-send */ }
        }
        return;
    }
    if (data.type === 'privasys:session:ws-close') {
        const id = data.id as number;
        const ws = activeWebSockets.get(id);
        if (ws) {
            activeWebSockets.delete(id);
            ws.close(typeof data.code === 'number' ? data.code : 1000, String(data.reason ?? ''));
        }
        return;
    }
});

/**
 * Normalise an enclave-supplied expiry to epoch ms. The wire contract
 * uses epoch seconds (crypto-contract §3); older Go enclaves sent epoch
 * ms. Values below 1e12 cannot be a sane epoch-ms after Sep 2001, so
 * they are treated as seconds.
 */
function normalizeEpochMs(v: number | undefined): number {
    if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) return 0;
    return v < 1e12 ? v * 1000 : v;
}

async function installSessionRelay(
    binding: { sessionId: string; encPub: string; expiresAt?: number },
    parentOrigin: string,
): Promise<void> {
    if (!pendingHandshake) {
        console.warn('[frame-host] sessionRelay returned without pending handshake — ignoring');
        return;
    }
    const { sdkKeyPair, appHost, key } = pendingHandshake;
    pendingHandshake = null;
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

if (window.opener && window.parent === window && globalThis.location.hash === DEVICE_POPUP_HASH) {
    // This page was opened as the device popup, not embedded as the gate.
    runDevicePopup();
} else {
    // Signal to parent that the iframe is ready to receive messages
    window.parent.postMessage({ type: 'privasys:ready' }, '*');
}
