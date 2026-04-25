// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

export { PrivasysAuth } from './client';
export { WebAuthnClient } from './webauthn';
export { AuthUI } from './ui';
export type { AuthUIConfig, SignInResult } from './ui';
export type {
    AuthConfig,
    AuthResult,
    AuthSession,
    AttestationInfo,
    AuthEvents,
    AuthState,
    BatchAppConfig,
    BatchAuthResult,
} from './types';
export type { WebAuthnConfig, WebAuthnState, WebAuthnEvents } from './webauthn';
export { generateQRPayload, generateBatchQRPayload, generateSessionId } from './qr';
export { SessionManager } from './session';
export { AuthFrame } from './frame-client';
export type { AuthFrameConfig } from './frame-client';
export { PrivasysSession } from './enclave-session';
export type {
    SessionInitOptions,
    WalletAttestationResult,
    SealedResponse,
} from './enclave-session';
