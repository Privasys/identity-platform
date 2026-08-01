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
export { AuthFrame, ConnectError, InsufficientCreditsError } from './frame-client';
export type {
    AttributeDisclosure,
    AuthFrameConfig,
    ConnectResult,
    PrivasysScope,
    RestoredSession,
    SealedResponse,
    SealedSession,
    SealedStreamResponse,
} from './frame-client';
export {
    ATTRIBUTE_MAP,
    CANONICAL_ATTRIBUTES,
    CANONICAL_KEYS,
    GOV_VERIFIED,
    SELF_ASSERTED,
    assuranceOf,
    attributePairs,
    fetchAttributeReferential,
    isBillable,
    isGovVerified,
    marketplaceKeyOf,
    requestableAttributes,
} from './attributes';
export type { AttributeMarketplace, CanonicalAttribute } from './attributes';
export { AttributePicker, assuranceLabel, attributeBadge, attributeLabel } from './attributes-ui';
export type { AttributeAssuranceBadge, AttributePickerConfig } from './attributes-ui';
export { PrivasysSession } from './enclave-session';
export type {
    EncAuthRejectReason,
    SessionInitOptions,
    WalletAttestationResult,
} from './enclave-session';
