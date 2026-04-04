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
export { generateQRPayload, generateBatchQRPayload, generateSessionId } from './qr';
export { SessionManager } from './session';
