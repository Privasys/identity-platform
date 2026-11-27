// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The configuration of the built-in gate and what a sign-in resolves with.
 */

import type { GateState } from '../gate-headless';
import type { OwnRegistration } from '../providers';
import type { AuthTheme } from '../theme';
import type { AttestationInfo, SessionRelayBinding } from '../types';

/** Configuration for the built-in auth UI. */
export interface AuthUIConfig {
    /** App name or UUID as registered on the platform. */
    appName: string;
    /** Relying party ID. Defaults to `appName` (used as-is). Set this to
     *  the full RP domain like `"my-app.apps.privasys.org"` if different. */
    rpId?: string;
    /** WebSocket URL for the auth broker relay. */
    brokerUrl?: string;
    /** Timeout in milliseconds for the entire flow (default: 120 000). */
    timeout?: number;
    /** Custom element to mount the overlay into (default: document.body). */
    container?: HTMLElement;
    /** Called with the rendered UI's height in CSS pixels whenever it
     *  changes, so a host that embeds this UI in an iframe can size the
     *  iframe to its content (see frame-size.ts). */
    onContentHeight?: (px: number) => void;
    /** Presentation mode. `'modal'` (default) renders the full-page chrome:
     *  brand panel, close button, spanning footer. `'inline'` renders a
     *  single compact column without brand panel or close button, sized to
     *  fit an adopter-provided container, sized to its content — the embedding
     *  page owns the surrounding content and dismissal. `'page'` renders
     *  the whole gate: the two-column layout with the adopter's `pitch`
     *  content (SDK-styled) in the left panel and no close button. */
    presentation?: 'modal' | 'inline' | 'page';
    /** Which sign-in methods to offer. Defaults to all available. A site
     *  that already showed its own identity chooser (e.g. "Connect with
     *  Privasys" next to "Connect with Google") passes `['wallet']` — the
     *  menu screen is skipped and the wallet flow starts immediately
     *  (push when the device is trusted, QR otherwise). */
    methods?: readonly ('wallet' | 'passkey' | 'social')[];
    /** App-provided content for the left panel in `'page'` presentation.
     *  Plain strings only (rendered as text, SDK-styled); sanitised and
     *  length-capped by the frame host. `logoUrl` (https only) renders the
     *  consumer's logo above the title. */
    pitch?: { title?: string; description?: string; bullets?: string[]; logoUrl?: string };
    /** Adopter theme, a closed set of tokens sanitised by the frame host. */
    theme?: AuthTheme;
    /** `false` hides the terms line in inline and page presentations, for a
     *  page that carries its own terms. A modal is Privasys's own surface and
     *  keeps it. */
    legal?: boolean;
    /** App identity for the templated gate header (`'page'` presentation):
     *  the app's logo and display name lead the header, with "Secured by
     *  Privasys ID" as the trust seal and a Close control on the right.
     *  `displayName` defaults to a prettified `appName`; `logoUrl` (https
     *  only, sanitised by the frame host) falls back to the Privasys mark. */
    app?: { logoUrl?: string; displayName?: string };
    /** Performs the wallet-handoff navigation via the ADOPTER page
     *  (frame host posts `privasys:navigate` to the parent). WebKit
     *  blocks custom-scheme navigations initiated by cross-origin
     *  iframes — even with target=_top it surfaces Safari's "address is
     *  invalid" alert with the app installed. The parent page is
     *  top-level and first-party, and the tap's transient user activation
     *  propagates to ancestors.
     *  Present only when the frame client is new enough to handle the
     *  message; older clients fall back to the direct _top anchor. */
    onNavigate?: (url: string) => void;
    /** Checks whether the OIDC session completed server-side (the IdP's
     *  poll endpoint). Supplied by the frame host. This is
     *  the same-device recovery path: when the user switches to the
     *  wallet app, the page is backgrounded and the broker WebSocket can
     *  die — the wallet's relay then lands in the void. The watcher polls
     *  this (and fires on visibilitychange) so the ceremony completes
     *  from the IdP's state instead of stranding on a dead socket. */
    checkComplete?: () => Promise<boolean>;
    /** Approve-only flow: re-verify an already-signed-in session against a
     *  changed enclave via a one-tap wallet push. When set, `signIn()`
     *  renders the approval waiting UI and delegates the push + sealed
     *  resume to `run()`. On success the ceremony resolves with an empty
     *  token payload (the frame host posts the real result); on failure the
     *  user can retry or fall back ("Sign in another way" rejects with
     *  `approve-fallback` so the host runs the full ceremony). */
    approveFlow?: {
        appLabel: string;
        /** Why re-approval is needed:
         *  'workload-changed' | 'enc-changed' | 'attributes-widened' | null. */
        reason?: string | null;
        /** For 'attributes-widened': the attribute keys the request added,
         *  so the waiting screen names exactly what changed. */
        added?: string[];
        /** May reject with `approve-fallback` to leave the approve flow and
         *  have the host run the full ceremony. */
        run: () => Promise<void>;
    };
    /** Approve one operation someone started elsewhere, not a sign-in. The
     *  wallet was notified when the operation was asked for; the gate shows
     *  that, the QR code that
     *  opens the approval in the wallet, and a passkey fallback, and waits.
     *  `signIn()` resolves once `wait()` does, with an empty result. */
    operationApproval?: {
        /** The wallet link that opens this approval. */
        walletLink: string;
        /** Approve with a passkey on this computer instead; absent when the
         *  page cannot. */
        onPasskey?: () => void;
        /** Resolves once the operation is approved; rejects with the reason
         *  it will not be (declined, expired). */
        wait: () => Promise<void>;
    };
    /** Stay open on success, showing this outcome, instead of closing: for a
     *  page whose whole purpose was the approval (a device's sign-in, an
     *  operation), so the person ends on the same view they approved in. */
    finalScreen?: { title: string; message: string };
    /** A way to refuse the request from the gate itself, under the
     *  ceremony: `run` refuses it, and the gate then stays on `title` and
     *  `message`. */
    decline?: { label: string; title: string; message: string; run: () => Promise<void> };
    /** Push token from a previous session. When present the UI will offer
     *  to send a push notification instead of showing a QR code. */
    pushToken?: string;
    /** Pre-assigned session ID. When set, the QR code and
     *  FIDO2 requests use this ID so the IdP can link them back to the
     *  OIDC authorize session. */
    sessionId?: string;
    /** OIDC client_id. Forwarded to the wallet via the QR
     *  descriptor / push payload so the EncAuth voucher lands on the same
     *  IdP session row (`sid`) as the issued JWT. */
    clientId?: string;
    /** Attribute keys the relying party needs from the wallet (e.g. ["email", "name"]). */
    requestedAttributes?: string[];
    /** Per-attribute essential/assurance hints from the IdP.
     *  Gov attributes are only disclosed as enclave-signed tokens when the
     *  wallet sees `assurance: 'gov'` here. */
    attributeRequirements?: import('../qr').AttributeRequirements;
    /** Paid-disclosure vouchers from the IdP authorize response.
     *  Relayed to the wallet via the QR descriptor / push payload. */
    disclosureVouchers?: import('../qr').DisclosureVoucher[];
    /** The identity provider's FIDO2 API for passkeys. Defaults to
     *  `/fido2` on this document's origin. */
    fido2Base?: string;
    /** Available social identity providers. Each entry is a
     *  provider name like "github", "google", "microsoft", "linkedin". */
    socialProviders?: string[];
    /** Names the identity provider publishes for a client's own registrations. */
    socialDisplayNames?: Record<string, string>;
    /** Icon addresses (https, sanitised by the host) for a client's own registrations, drawn as images. */
    socialIcons?: Record<string, string>;
    /** The client's own registrations offered as buttons of their own, first among the alternatives. */
    socialOwn?: OwnRegistration[];
    /** Callback when the user wants to start social auth. The UI calls
     *  this with the provider name; the host opens a popup. */
    onSocialAuth?: (provider: string, own?: boolean, chooseAccount?: boolean) => Promise<void>;
    /**
     * Ask whether this browser already knows the person's phone, on a site
     * whose own copy of the gate's storage does not. The host opens a short
     * popup on the identity provider's origin, which sees the one storage
     * every site shares; it must be called inside the click, since a browser
     * only allows a popup then. Resolves null when nothing is remembered or
     * the popup could not open.
     */
    lookupDevice?: () => Promise<{ pushToken: string; label: string }[]>;
    /**
     * The wallets this browser remembers on this site, the most recently
     * used first. With several, the gate shows one button each and starts
     * nothing by itself; with one, `pushToken` is it.
     */
    devices?: { pushToken: string; label: string }[];
    /** Forget a remembered wallet, here and for every site. Called inside
     *  the click on "Forget". */
    forgetDevice?: (pushToken: string) => Promise<void> | void;
    /** Remember the phone for every site in this browser, the same way.
     *  Called inside the click on "Trust this device"; the gate waits for it
     *  before it finishes, so the frame is still there to answer the popup. */
    rememberDevice?: (pushToken: string, label?: string) => Promise<void> | void;
    /**
     * The client asked for the person's name or email address, which a
     * passkey does not carry. After a passkey the gate then asks the person
     * to sign in once with an account provider, whose answer the identity
     * provider adds to this sign-in.
     */
    profileAfterPasskey?: boolean;
    /** Headless: the gate renders nothing the person sees; the embedding
     *  page draws the buttons from `gateOptions()` and calls `start()`.
     *  No flow starts on its own except a re-approval. */
    headless?: boolean;
    /** Every change of state, for a headless page to narrate. */
    onGateState?: (state: GateState) => void;
    /** URL to the app's privacy policy. Shown to the user when sharing attributes. */
    privacyPolicyUrl?: string;
    /** When true, the device is already trusted (device hint exists). The trust
     *  prompt is suppressed and `trustDevice` is set automatically. */
    deviceTrusted?: boolean;
    /**
     * Session-relay opt-in. When set, the QR carries `mode: 'session-relay'`
     * plus the SDK ephemeral pubkey and `appHost`, and the wallet returns
     * the enclave-issued `sessionId` + `encPub` over the broker so the SDK
     * can derive the AES-GCM key and instantiate `PrivasysSession`.
     */
    sessionRelay?: { sdkPub: string; appHost: string; extraAppHosts?: string[]; nonce?: string; spend?: { cap?: number } };
}

/** Resolved result returned by `signIn()`. */
export interface SignInResult {
    /** Opaque session token issued by the enclave. */
    sessionToken: string;
    /** Method used: "wallet" or "passkey". */
    method: 'wallet' | 'passkey';
    /** Attestation info (wallet only). */
    attestation?: AttestationInfo;
    /** Session ID. */
    sessionId: string;
    /** Push token for sending future auth requests (wallet only). */
    pushToken?: string;
    /** The wallet's name for this phone, when it sent one. */
    deviceLabel?: string;
    /** Profile attributes from the wallet (keyed by OIDC claim name). */
    attributes?: Record<string, string>;
    /** Whether the user chose to trust this device for future push-based sign-in. */
    trustDevice?: boolean;
    /** Session-relay binding from the wallet (set only in session-relay mode). */
    sessionRelay?: SessionRelayBinding;
    /** True when the ceremony completed via the IdP status poll rather
     *  than the broker relay (same-device flow: the relay died during
     *  the app switch). The frame host then fetches the auth code from
     *  the poll endpoint and recovers the sealed binding from the
     *  wallet's EncAuth voucher. */
    completedViaPoll?: boolean;
}

export type UIState =
    | 'idle'
    | 'profile-required'
    | 'push-waiting'
    | 'qr-scanning'
    | 'wallet-connected'
    | 'authenticating'
    | 'approve-waiting'
    | 'passkey-requesting'
    | 'passkey-ceremony'
    | 'passkey-verifying'
    | 'success'
    | 'error';
