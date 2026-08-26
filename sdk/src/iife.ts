// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * IIFE entry point — exposes a flat `window.Privasys` namespace for
 * <script> tag usage. Does NOT include React bindings.
 *
 * Usage:
 *   <script src="https://sdk.privasys.org/v1/privasys-auth.js"></script>
 *   <script>
 *     const webauthn = new Privasys.WebAuthnClient({ apiBase: '...', appName: '...' });
 *     const result = await webauthn.register();
 *   </script>
 */

export { PrivasysAuth } from './client';
export { WebAuthnClient } from './webauthn';
export { AuthUI } from './ui';
export { generateQRPayload, generateSessionId } from './qr';
export { SessionManager } from './session';
export {
    ATTRIBUTE_MAP, CANONICAL_ATTRIBUTES, CANONICAL_KEYS,
    assuranceOf, attributePairs, fetchAttributeReferential,
    isBillable, isGovVerified, marketplaceKeyOf, requestableAttributes,
} from './attributes';
export { AttributePicker, assuranceLabel, attributeBadge, attributeLabel } from './attributes-ui';
