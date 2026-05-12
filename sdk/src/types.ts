// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/** Configuration for a Privasys Auth request. */
export interface AuthConfig {
    /** The relying party ID (e.g., "myapp.apps.privasys.org"). */
    rpId: string;
    /**
     * Hostname (no scheme) of the IdP that runs the FIDO2 ceremony for
     * this app. Defaults to `"privasys.id"`. Set this only if you are
     * running a self-hosted IdP. The wallet uses this as the `origin`
     * in `clientDataJSON` and as the host it POSTs `/fido2/*` against.
     */
    idpOrigin?: string;
    /** WebSocket URL for the auth broker relay. */
    brokerUrl: string;
    /** Whether to require attestation verification on the wallet. */
    attestation?: 'required' | 'preferred' | 'none';
    /** Timeout in milliseconds (default: 120000). */
    timeout?: number;
    /** Attribute keys the relying party needs from the wallet (e.g. ["email", "name"]). */
    requestedAttributes?: string[];
    /** Human-readable app name displayed in the wallet during consent. */
    appName?: string;
    /** URL to the app's privacy policy. Shown to the user when sharing attributes. */
    privacyPolicyUrl?: string;
}

/** Attestation information returned from the wallet. */
export interface AttestationInfo {
    teeType: 'sgx' | 'tdx';
    mrenclave?: string;
    mrtd?: string;
    codeHash?: string;
    configRoot?: string;
    quoteVerificationStatus?: string;
    valid: boolean;
}

/** Result of a successful authentication. */
export interface AuthResult {
    /** Opaque session token issued by the enclave. */
    sessionToken: string;
    /** Attestation info if the wallet verified the enclave. */
    attestation?: AttestationInfo;
    /** The session ID used for this authentication. */
    sessionId: string;
    /** Push token for sending future auth requests (wallet only). */
    pushToken?: string;
    /** Profile attributes from the wallet or social IdP (keyed by OIDC claim name). */
    attributes?: Record<string, string>;
    /**
     * Session-relay binding returned by the wallet when the QR opted into
     * `mode: 'session-relay'`. The SDK uses these to derive the AES-GCM key
     * shared with the enclave and instantiate a `PrivasysSession`.
     */
    sessionRelay?: SessionRelayBinding;
}

/**
 * Wallet-attested session-relay binding. Returned to the SDK over the
 * broker so the SDK can complete its half of the ECDH handshake.
 */
export interface SessionRelayBinding {
    /** Opaque session id (>=16 bytes), base64url. */
    sessionId: string;
    /** Enclave's ephemeral P-256 public key (SEC1 uncompressed, base64url). */
    encPub: string;
    /** Enclave-side session expiry (epoch ms). */
    expiresAt: number;
}

/** An active session with an enclave. */
export interface AuthSession {
    /** The session token. */
    token: string;
    /** The RP this session is with. */
    rpId: string;
    /** Origin of the enclave. */
    origin: string;
    /** When this session was established (epoch ms). */
    authenticatedAt: number;
    /** Push token for the wallet that authenticated (if available). */
    pushToken?: string;
    /** Broker WebSocket URL used for this session (needed for push auth). */
    brokerUrl?: string;
    /** OIDC refresh token for silent session renewal (replaces push-based renewal). */
    refreshToken?: string;
    /** OIDC client_id used for this session (needed for refresh_token grant). */
    clientId?: string;
}

/** Events emitted by the auth client. */
export interface AuthEvents {
    /** Called when authentication completes successfully. */
    onAuthenticated?: (result: AuthResult) => void;
    /** Called when the session expires or is invalidated. */
    onSessionExpired?: (rpId: string) => void;
    /** Called when the auth state changes (e.g., waiting, scanning, connected). */
    onStateChange?: (state: AuthState) => void;
    /** Called on error. */
    onError?: (error: Error) => void;
}

/** Configuration for one app in a batch auth request. */
export interface BatchAppConfig {
    rpId: string;
    brokerUrl: string;
    attestation?: 'required' | 'preferred' | 'none';
}

/** Result of a batch authentication (one entry per app). */
export interface BatchAuthResult {
    results: AuthResult[];
    /** Apps that failed authentication. */
    errors: Array<{ rpId: string; error: string }>;
}

/** The current state of an auth request. */
export type AuthState =
    | 'idle'
    | 'waiting-for-scan'
    | 'wallet-connected'
    | 'authenticating'
    | 'complete'
    | 'error'
    | 'timeout';
