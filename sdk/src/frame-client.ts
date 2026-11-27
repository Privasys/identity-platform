// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * The hosted client bundle (`privasys-auth-client.iife.js`), as the global
 * `Privasys`: {@link AuthFrame} for every site, and {@link IdpGate} for the
 * identity provider's own pages.
 */

export { AuthFrame } from './client/auth-frame';
export { ConnectError, InsufficientCreditsError } from './client/types';
export { IdpGate } from './idp';
