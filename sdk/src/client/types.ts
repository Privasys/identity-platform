// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The page-side API's types: the configuration of an {@link AuthFrame}, the
 * session it holds, the channels it opens to enclave apps, and its errors.
 */

import type { GateControls, GateOptions, GateState } from '../gate-headless';
import type { SocialProvider } from '../providers';
import type { AuthTheme } from '../theme';

/**
 * OIDC scope tokens. A scope is a coarse bundle of attributes (see the
 * `scope` field of the canonical referential). Every government-backed
 * `_id` attribute and every priced attribute is request-only: name it in
 * {@link AuthFrameConfig.attributes}. `offline_access` issues a refresh token.
 */
export type PrivasysScope = 'openid' | 'email' | 'profile' | 'phone' | 'identity' | 'offline_access';

/**
 * A gov-verified attribute disclosure: an enclave-signed SD-JWT VC
 * (`typ: dc+sd-jwt`) minted by the identity-verifier enclave from a
 * government document.
 *
 * Store {@link token} as the durable receipt: it is re-verifiable offline
 * (issuer JWKS at `{issuer}/.well-known/jwt-vc-issuer`) and its `evidence`
 * ties the claim to the attested enclave and the paid disclosure.
 */
export interface AttributeDisclosure {
    /** Canonical attribute key, e.g. `"age_over_18"`. */
    claim: string;
    /** Disclosed value from the credential payload (e.g. `true`, `"GBR"`). */
    value: unknown;
    /** Assurance level: `"gov"` for document-verified claims. */
    assurance?: string;
    /** Issuance evidence: `ivr`, `measurement`, `issuing_state`, `verified_at`, `voucher`. */
    evidence?: Record<string, unknown>;
    /** Credential issuer (the verifier enclave origin). */
    issuer?: string;
    /** Epoch seconds the credential was issued. */
    issuedAt?: number;
    /** Epoch seconds the credential expires; the stored token stays the
     *  receipt of what was verified at `issuedAt`. */
    expiresAt?: number;
    /** The raw SD-JWT VC. Persist this, not just the value. */
    token: string;
}

/** How a device sign-in or an operation approval ended without approval. */
export type GateOutcome = 'declined' | 'decline-failed' | 'approval-failed';

/** The person's session with this site's client. */
export interface Session {
    /** Access token for {@link AuthFrameConfig.audience} (or the client's default audience). */
    token: string;
    /** How the person signed in. */
    method: 'wallet' | 'passkey' | 'social';
    /** When {@link token} expires, epoch ms. */
    expiresAt: number;
    /** Gov-verified disclosures from the sign-in that created the session. */
    disclosures?: AttributeDisclosure[];
}

/** Why {@link AuthFrame.connect} failed. */
export class ConnectError extends Error {
    /** 'cancelled': the person dismissed the gate; 'timeout': it was not
     *  completed in time; 'failed': anything else. */
    readonly code: 'cancelled' | 'timeout' | 'failed';
    constructor(code: 'cancelled' | 'timeout' | 'failed', message: string) {
        super(message);
        this.name = 'ConnectError';
        this.code = code;
    }
}

/**
 * The sign-in was refused because the client's billing account cannot cover
 * the requested gov-verified attributes. The person was never prompted; top
 * up the account and retry. A {@link ConnectError} with code 'failed'.
 */
export class InsufficientCreditsError extends ConnectError {
    constructor(message?: string) {
        super('failed', message || 'Insufficient credits for the requested attributes');
        this.name = 'InsufficientCreditsError';
    }
}

/**
 * A page that draws its own sign-in buttons. The frame stays invisible and
 * runs every flow: it reports the options for this client, the page renders
 * them and starts one, and the frame reports the flow's progress. External
 * providers still sign in through a popup on the identity provider's origin,
 * which the page opens at the address the frame names. Passkeys are not
 * offered headless: a passkey needs a click inside the frame.
 */
export interface HeadlessGate {
    /** The options for this client. Draw them and keep `gate` to start the
     *  one the person chooses. Called again on every new sign-in attempt. */
    onOptions: (options: GateOptions, gate: GateControls) => void;
    /** Where the started flow is: `push-waiting`, `qr-scanning` (show
     *  `qrSvg`), `authenticating`, `success`, `error` (show `error`). */
    onState?: (state: GateState) => void;
}

/** How the gate looks: shared by {@link AuthFrameConfig} and the identity provider's own gate. */
export interface GateAppearance {
    /** Shown on the gate and in the wallet. */
    appName: string;
    /**
     * Mount the gate inside this element instead of as a full-screen modal.
     * The gate sizes itself to its content. Implies `presentation: 'inline'`.
     */
    container?: HTMLElement;
    /** `'modal'` (default without a container), `'inline'` (default with
     *  one), or `'page'`: the whole two-column gate with `pitch`. */
    presentation?: 'modal' | 'inline' | 'page';
    /** Plain-text content for the left panel of a `'page'` gate: title
     *  (120), description (600), up to 5 bullets (200 each), https logo. */
    pitch?: { title?: string; description?: string; bullets?: string[]; logoUrl?: string };
    /** Your app's logo (https) and display name for the gate's header. */
    app?: { logoUrl?: string; displayName?: string };
    /** Theme tokens (font, colours, radius), used as given. The "Secured by
     *  Privasys ID" seal stays in every theme. */
    theme?: AuthTheme;
    /** `false` hides the terms line in `'inline'` and `'page'` gates. */
    legal?: boolean;
    /** Timeout of the gate in ms (default: 120 000). */
    timeout?: number;
    /** Origin of the identity provider (default: "https://privasys.id"). */
    authOrigin?: string;
    /** WebSocket URL of the wallet relay. */
    brokerUrl?: string;
}

export interface AuthFrameConfig extends GateAppearance {
    /** This website's client at the identity provider. One per website. */
    clientId: string;
    /**
     * Enclave hosts the wallet approves within the sign-in itself: one tap
     * signs the person in and approves these apps, so {@link AuthFrame.app}
     * opens their sealed channels without asking again.
     */
    apps?: readonly string[];
    /** Scopes to request. `'openid'` is always included.
     *  @default ['openid', 'offline_access'] */
    scope?: readonly PrivasysScope[];
    /**
     * Canonical attribute keys to request by name, alongside the scope. For
     * a government-backed key this is the only way. A key the identity
     * provider does not know is dropped, not refused.
     * @example ['given_name_id', 'birthdate_id']
     */
    attributes?: readonly string[];
    /**
     * The audience of the session's token, for an app that authorises on it
     * (`app:<app id>`). The identity provider keeps no profile, so the first
     * token is the only one that can carry the person's name and email:
     * store what you need on first sight.
     */
    audience?: string;
    /** Which sign-in methods the gate offers, in this order. Defaults to all.
     *  `['wallet']` skips the menu and starts the wallet flow. */
    methods?: readonly ('wallet' | 'passkey' | 'social')[];
    /** Which external identity providers `'social'` offers, in this order:
     *  the shared ones and the client's own federation. Defaults to every
     *  provider the identity provider has for this client. */
    providers?: readonly SocialProvider[];
    /** Draw the gate yourself. `container`, `presentation`, `pitch`,
     *  `theme` and `legal` then have no effect. */
    headless?: HeadlessGate;
    /** Ask, at sign-in, to spend the person's credits under a monthly cap
     *  (in credits; 1 credit = £0.000001). Needs `apps`: the wallet shows
     *  the consent beside the app's attested identity. */
    spend?: { cap?: number };
    /** Opaque billing grant forwarded to the identity provider: the cost of
     *  any paid disclosure this sign-in triggers goes to the grant's issuer. */
    billingGrant?: string;
    /** Your privacy policy, shown when attributes are shared. */
    privacyPolicyUrl?: string;
}

/** A response from an enclave app, whichever way it travelled. */
export interface AppResponse {
    status: number;
    headers: Record<string, string>;
    body: Uint8Array;
    transport: 'sealed' | 'direct';
}

/** A streamed response from an enclave app (server-sent events, chunks). */
export interface AppStreamResponse {
    status: number;
    headers: Record<string, string>;
    body: ReadableStream<Uint8Array>;
    transport: 'sealed' | 'direct';
}

/** A WebSocket to an enclave app: binary messages, sealed or direct. */
export interface AppWebSocket {
    /** Resolves when open; rejects if it closes first. */
    readonly ready: Promise<void>;
    readonly open: boolean;
    /** Bytes, a string or JSON. Sent once open, in order. */
    send(data: Uint8Array | ArrayBuffer | string | object): void;
    onMessage(cb: (data: Uint8Array) => void): () => void;
    onClose(cb: (info: { code: number; reason: string; wasClean: boolean }) => void): void;
    onError(cb: (err: Error) => void): void;
    close(code?: number, reason?: string): void;
}

/**
 * How the page reaches one enclave app: sealed for a wallet session, direct
 * (HTTPS with an audience token) otherwise. `state` is `ok`, `reconnecting`
 * (the SDK is re-establishing it), or `signed-out` (it cannot continue: call
 * {@link AuthFrame.app} again, after {@link AuthFrame.connect} when the
 * session ended).
 */
export interface AppChannel {
    readonly transport: 'sealed' | 'direct';
    /** `path` starts with "/" and may carry a query string; `body` is sent
     *  as is when bytes or a string, as JSON otherwise. */
    request(method: string, path: string, body?: unknown, init?: RequestInit): Promise<AppResponse>;
    stream(method: string, path: string, body?: unknown, init?: RequestInit): Promise<AppStreamResponse>;
    openWebSocket(path: string): Promise<AppWebSocket>;
    readonly state: 'ok' | 'reconnecting' | 'signed-out';
    onState(cb: (state: 'ok' | 'reconnecting' | 'signed-out') => void): () => void;
}
