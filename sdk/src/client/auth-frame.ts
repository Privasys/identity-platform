// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * AuthFrame: the person's session with this site's client, and the channels
 * to the enclave apps they use. One per page.
 *
 * ```html
 * <script src="https://privasys.id/auth/privasys-auth-client.iife.js"></script>
 * <script>
 *   const auth = new Privasys.AuthFrame({ clientId: 'my-site', appName: 'My Site' });
 *   const session = await auth.connect();
 *   const api = await auth.app('my-app.apps.privasys.org', { audience: 'app:<app id>' });
 *   const res = await api.request('GET', '/me');
 * </script>
 * ```
 *
 * The sign-in runs in a frame on the identity provider's origin, which keeps
 * the session in its own storage: shared by every tab of this site, and by
 * no other site. A hidden frame stays mounted for the page's life: it renews
 * the session, mints tokens, reports every change to the session, and holds
 * the keys of every sealed channel.
 */

import { Channel, SealedBridge, directTransport } from './app-channel';
import { openGate, type GateResult, type GateRun } from './gate-frame';
import { approvalReason, appHost, channelState, parseView, sessionOf, widenedBy, type SessionView } from './session';
import { SessionFrame } from './session-frame';
import { ConnectError, type AppChannel, type AuthFrameConfig, type HeadlessGate, type Session } from './types';

const DEFAULT_AUTH_ORIGIN = 'https://privasys.id';

export class AuthFrame {
    private readonly authOrigin: string;
    private config: Omit<AuthFrameConfig, 'container' | 'headless' | 'authOrigin'>;
    private container: HTMLElement | null;
    private readonly headless: HeadlessGate | null;
    private readonly frame: SessionFrame;
    private readonly sealed: SealedBridge;
    private current: Session | null = null;
    /** Whether the frame has reported the stored session yet. */
    private known = false;
    private loading: Promise<SessionView | null> | null = null;
    private readonly listeners = new Set<(s: Session | null) => void>();
    private gate: GateRun | null = null;
    private readonly channels = new Map<string, Channel>();
    private readonly opening = new Map<string, Promise<void>>();
    /** Hosts the wallet approved in this page's last sign-in, and how long
     *  their vouchers may take to land. */
    private readonly approvedAtSignIn = new Map<string, number>();
    private destroyed = false;

    constructor(config: AuthFrameConfig) {
        if (!config || typeof config.clientId !== 'string' || !config.clientId) {
            throw new Error('AuthFrame: clientId is required');
        }
        const { authOrigin, container, headless, ...rest } = config;
        this.authOrigin = authOrigin ?? DEFAULT_AUTH_ORIGIN;
        this.container = container ?? null;
        this.headless = headless ?? null;
        this.config = rest;
        this.frame = new SessionFrame(this.authOrigin, (data) => this.onFrameEvent(data));
        this.sealed = new SealedBridge(this.frame);
        const key = `${this.authOrigin}|${config.clientId}`;
        const live = (liveFrames.get(key) ?? 0) + 1;
        liveFrames.set(key, live);
        if (live > 1) {
            console.warn(`[privasys] ${live} AuthFrame instances are alive for ${config.clientId}; keep one per page and call app() on it for every enclave.`);
        }
    }

    /** The current session, kept in step across tabs; null when signed out
     *  or before the frame has reported it. */
    get session(): Session | null {
        return this.current;
    }

    /**
     * Be told of every change to the session: sign-in, renewal, sign-out and
     * expiry, from any tab of the site. Called once with the stored session
     * (or null) when the frame first reports it, then on each change.
     * Returns an unsubscribe function.
     */
    onSessionChange(cb: (session: Session | null) => void): () => void {
        this.listeners.add(cb);
        if (!this.known) void this.load().catch(() => undefined);
        return () => this.listeners.delete(cb);
    }

    /**
     * Restore the session silently, or run the gate (any method the
     * configuration offers). A stored session minted for fewer attributes or
     * scopes than the configuration asks for runs the gate, which asks the
     * wallet for the difference. Rejects with a {@link ConnectError}
     * (`cancelled`, `timeout`, `failed`); {@link InsufficientCreditsError}
     * is one.
     *
     * @param opts.container where to render the gate this time, for a page
     *   that mounted a new container since.
     * @param opts.attributes attributes this sign-in also needs (a step-up):
     *   they join the frame's `attributes`, and a session without them runs
     *   the gate, which asks the wallet for the difference.
     * @param opts.billingGrant a billing grant for this ceremony only.
     * @param opts.methods the sign-in methods this ceremony offers, when it
     *   needs fewer than the configuration's (only the wallet can share
     *   certified attributes, for example).
     */
    async connect(opts?: {
        container?: HTMLElement;
        attributes?: readonly string[];
        billingGrant?: string;
        methods?: AuthFrameConfig['methods'];
    }): Promise<Session> {
        this.alive();
        if (opts?.container) this.container = opts.container;
        if (opts?.attributes?.length) {
            const merged = new Set([...(this.config.attributes ?? []), ...opts.attributes]);
            this.config = { ...this.config, attributes: [...merged] };
        }
        const view = await this.load().catch(() => null);
        if (view && !widenedBy(this.config, view)) return this.current!;

        const result = await this.ceremony({
            ...(opts?.billingGrant ? { billingGrant: opts.billingGrant } : {}),
            ...(opts?.methods?.length ? { methods: [...opts.methods] } : {}),
        });
        if (!result.accessToken) throw new ConnectError('failed', 'The sign-in returned no session');
        for (const host of result.apps?.hosts ?? []) this.approvedAtSignIn.set(host, result.apps!.waitMs);
        this.apply({
            token: result.accessToken,
            method: result.method ?? 'passkey',
            requestedAttributes: [...(this.config.attributes ?? [])],
            scope: this.scopeString(),
        });
        // The persistent frame takes over the new session's renewal.
        await this.frame.call({ type: 'privasys:check-session', clientId: this.config.clientId }, 'privasys:session', 15_000)
            .catch(() => undefined);
        return this.current!;
    }

    /**
     * The session's token, or one minted for `audience` (another service's
     * audience, or `app:<app id>`), without replacing the session's own.
     */
    async token(audience?: string): Promise<string> {
        const session = await this.signedIn();
        if (!audience) return session.token;
        const r = await this.frame.call(
            { type: 'privasys:get-token-for-audience', clientId: this.config.clientId, audience },
            'privasys:token-for-audience:response',
            20_000,
        );
        if (typeof r.error === 'string') throw new Error(r.error);
        if (typeof r.accessToken !== 'string') throw new Error('malformed response from the sign-in frame');
        return r.accessToken;
    }

    /**
     * Renew the session now, for a page that knows what the person may do
     * has changed (a role granted, an account switched). At most one renewal
     * per 10 s: a later call waits for the interval, then renews.
     */
    async renew(): Promise<Session> {
        await this.signedIn();
        const r = await this.frame.call(
            { type: 'privasys:renew-session', clientId: this.config.clientId },
            'privasys:renew-session:response',
            30_000,
        );
        if (typeof r.error === 'string') throw new Error(r.error);
        const view = parseView(r.session);
        if (!view) throw new Error('malformed response from the sign-in frame');
        this.apply(view);
        return this.current!;
    }

    /** End this client's session on this site, in every tab. */
    async signOut(): Promise<void> {
        this.alive();
        await this.frame.call({ type: 'privasys:clear-session', clientId: this.config.clientId }, 'privasys:session-cleared', 10_000)
            .catch(() => undefined);
        this.apply(null);
    }

    /**
     * The channel to the enclave app at `host` (a host name, no scheme). The
     * same host gives the same channel; a channel whose state is
     * `signed-out` is re-established by calling app() again.
     *
     * A wallet session reaches the app sealed: from the session's approval
     * for the host, or, without one, after one tap in the wallet
     * (`onApproval` is called while it waits, with null the first time and
     * the reason after a change: `enc-changed`, `workload-changed`,
     * `voucher-expired`). Any other session reaches it directly, over HTTPS
     * with a token for `audience`, which it then requires (`app:<app id>`).
     *
     * `transport: 'direct'` reaches the app over HTTPS whatever the sign-in
     * method, for an app served on a name that only takes direct calls.
     */
    async app(host: string, opts?: {
        audience?: string;
        onApproval?: (reason: string | null) => void;
        transport?: 'direct';
    }): Promise<AppChannel> {
        this.alive();
        const name = appHost(host);
        let channel = this.channels.get(name);
        if (!channel) {
            channel = new Channel(name);
            this.channels.set(name, channel);
        }
        if (opts?.audience) channel.audience = opts.audience;
        const session = await this.signedIn();
        if (session.method === 'wallet' && opts?.transport !== 'direct') {
            if (!channel.live('sealed')) await this.openSealed(channel, opts?.onApproval);
            return channel;
        }
        const audience = channel.audience;
        if (!audience) {
            throw new Error('AuthFrame: app() needs an audience (normally app:<app id>) for a direct channel');
        }
        if (!channel.live('direct')) channel.use(directTransport(name, () => this.token(audience)));
        return channel;
    }

    /**
     * Link a Privasys ID to a person signed in to your app another way. The
     * gate opens as a modal limited to the wallet; once approved, resolves
     * with an ID token for your client. Your server verifies its signature,
     * `aud` (your client id), `exp`, `nonce` (the value passed here) and that
     * `amr` contains `"webauthn"`; its `sub` is the person's Privasys ID
     * under your client. The page's session is neither read nor replaced.
     *
     * @param nonce 16 to 256 URL-safe characters, single use, made by your server.
     */
    async linkIdentity(nonce: string): Promise<string> {
        this.alive();
        if (!/^[A-Za-z0-9._~-]{16,256}$/.test(nonce)) {
            throw new Error('AuthFrame: linkIdentity needs a nonce of 16 to 256 URL-safe characters');
        }
        const result = await this.ceremony({ link: { nonce }, presentation: 'modal' }, true);
        if (!result.linked || !result.idToken) throw new Error('AuthFrame: the identity provider did not return a link');
        return result.idToken;
    }

    /** Cancel the gate in progress, if any: connect() rejects with 'cancelled'. */
    cancel(): void {
        this.gate?.cancel();
    }

    /** Remove every frame and close every channel. */
    destroy(): void {
        if (this.destroyed) return;
        this.destroyed = true;
        this.gate?.cancel();
        this.sealed.close();
        this.frame.destroy();
        for (const ch of this.channels.values()) ch.setState('signed-out');
        const key = `${this.authOrigin}|${this.config.clientId}`;
        const live = (liveFrames.get(key) ?? 1) - 1;
        if (live > 0) liveFrames.set(key, live);
        else liveFrames.delete(key);
    }

    // ── internals ───────────────────────────────────────────────────────

    private alive(): void {
        if (this.destroyed) throw new Error('AuthFrame: destroyed');
    }

    private scopeString(): string {
        return (this.config.scope ?? ['openid', 'offline_access']).join(' ');
    }

    /** Ask the persistent frame for the stored session (and to watch it). */
    private load(): Promise<SessionView | null> {
        if (this.loading) return this.loading;
        const p = this.frame.call({ type: 'privasys:check-session', clientId: this.config.clientId }, 'privasys:session', 15_000)
            .then((r) => {
                const view = parseView(r.session);
                this.apply(view);
                return view;
            })
            .finally(() => { if (this.loading === p) this.loading = null; });
        this.loading = p;
        return p;
    }

    /** The current session, from the frame if not known yet; throws when signed out. */
    private async signedIn(): Promise<Session> {
        this.alive();
        if (!this.known) await this.load().catch(() => null);
        if (!this.current) throw new Error('AuthFrame: not signed in; call connect() first');
        return this.current;
    }

    /** Take a reported session as the current one, and tell the listeners
     *  when it changed (or is reported for the first time). */
    private apply(view: SessionView | null): void {
        const first = !this.known;
        this.known = true;
        const before = this.current?.token ?? null;
        const after = view?.token ?? null;
        if (before === after && !first) return;
        if (before !== after) this.current = view ? sessionOf(view, this.current) : null;
        if (!view) for (const ch of this.channels.values()) ch.setState('signed-out');
        for (const cb of this.listeners) {
            try { cb(this.current); } catch { /* isolate listener errors */ }
        }
    }

    private onFrameEvent(data: Record<string, unknown>): void {
        if (data.type === 'privasys:session-changed') {
            if (data.clientId === this.config.clientId) this.apply(parseView(data.session));
            return;
        }
        if (data.type === 'privasys:session:state') {
            const channel = this.channels.get(String(data.host));
            if (channel?.transport === 'sealed') channel.setState(channelState(data.status));
            return;
        }
        this.sealed.handle(data);
    }

    /** Run the gate once; failures become {@link ConnectError}s. */
    private async ceremony(extra: Record<string, unknown>, modal = false): Promise<GateResult> {
        if (this.gate) throw new ConnectError('failed', 'AuthFrame: a sign-in is already in progress');
        const c = this.config;
        const container = modal ? null : this.container;
        const run = openGate({
            authOrigin: this.authOrigin,
            container,
            headless: modal ? null : this.headless,
            config: {
                appName: c.appName,
                clientId: c.clientId,
                scope: this.scopeString(),
                ...(c.attributes ? { attributes: [...c.attributes] } : {}),
                ...(c.audience ? { audience: c.audience } : {}),
                ...(c.methods ? { methods: [...c.methods] } : {}),
                ...(c.providers ? { providers: [...c.providers] } : {}),
                presentation: c.presentation ?? (container ? 'inline' : 'modal'),
                ...(c.pitch ? { pitch: c.pitch } : {}),
                ...(c.app ? { app: c.app } : {}),
                ...(c.theme ? { theme: c.theme } : {}),
                ...(c.legal === false ? { legal: false } : {}),
                ...(c.timeout ? { timeout: c.timeout } : {}),
                ...(c.brokerUrl ? { brokerUrl: c.brokerUrl } : {}),
                ...(c.privacyPolicyUrl ? { privacyPolicyUrl: c.privacyPolicyUrl } : {}),
                ...(c.billingGrant ? { billingGrant: c.billingGrant } : {}),
                ...(c.spend ? { spend: c.spend } : {}),
                ...(c.apps?.length ? { apps: [...c.apps] } : {}),
                ...extra,
            },
        });
        this.gate = run;
        try {
            return await run.done;
        } catch (err) {
            if (err instanceof ConnectError) throw err;
            const msg = err instanceof Error ? err.message : String(err);
            if (msg === 'Authentication cancelled') throw new ConnectError('cancelled', msg);
            if (/timeout|timed out/i.test(msg)) throw new ConnectError('timeout', msg);
            throw new ConnectError('failed', msg);
        } finally {
            this.gate = null;
        }
    }

    /** Establish the sealed channel of a host, once at a time. */
    private openSealed(channel: Channel, onApproval?: (reason: string | null) => void): Promise<void> {
        const pending = this.opening.get(channel.host);
        if (pending) return pending;
        const p = this.establishSealed(channel, onApproval).finally(() => this.opening.delete(channel.host));
        this.opening.set(channel.host, p);
        return p;
    }

    private async establishSealed(channel: Channel, onApproval?: (reason: string | null) => void): Promise<void> {
        const host = channel.host;
        const waitMs = this.approvedAtSignIn.get(host) ?? 0;
        this.approvedAtSignIn.delete(host);
        let r = await this.resume(host, { spend: !!this.config.spend, waitMs });
        if (r.error === 'rate-limited') {
            // The enclave budgets bootstraps per minute: wait it out once.
            await new Promise((res) => setTimeout(res, 15_000));
            r = await this.resume(host, { spend: !!this.config.spend, waitMs: 0 });
        }
        if (r.error) {
            const reason = approvalReason(r.error, r.reason);
            if (reason === undefined) throw new Error(r.reason ? `${r.error}:${r.reason}` : r.error);
            onApproval?.(reason);
            const v = await this.frame.call(
                { type: 'privasys:voucher-request', clientId: this.config.clientId, host, appName: this.config.appName },
                'privasys:voucher-request:response',
                150_000,
            );
            if (typeof v.error === 'string') throw new Error(v.error);
            r = await this.resume(host, { spend: false, waitMs: 0 });
            if (r.error) throw new Error(r.reason ? `${r.error}:${r.reason}` : r.error);
        }
        channel.use(this.sealed.transport(host));
    }

    private async resume(host: string, opts: { spend: boolean; waitMs: number }): Promise<{ error?: string; reason?: string }> {
        const r = await this.frame.call(
            {
                type: 'privasys:session:resume',
                clientId: this.config.clientId,
                host,
                ...(opts.spend ? { spend: true } : {}),
                ...(opts.waitMs ? { waitMs: opts.waitMs } : {}),
            },
            'privasys:session:resume:response',
            opts.waitMs + 60_000,
        );
        return {
            ...(typeof r.error === 'string' ? { error: r.error } : {}),
            ...(typeof r.reason === 'string' ? { reason: r.reason } : {}),
        };
    }
}

/** Live AuthFrame instances per identity provider and client; see the constructor. */
const liveFrames = new Map<string, number>();
