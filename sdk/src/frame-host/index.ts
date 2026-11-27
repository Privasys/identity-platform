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

import { DEVICE_POPUP_HASH, runDevicePopup } from './device-popup';
import { startRenewalWatch } from './renewal';
import { startRouter } from './router';

startRenewalWatch();
startRouter();

if (window.opener && window.parent === window && globalThis.location.hash === DEVICE_POPUP_HASH) {
    // This page was opened as the device popup, not embedded as the gate.
    runDevicePopup();
} else {
    // Signal to parent that the iframe is ready to receive messages
    window.parent.postMessage({ type: 'privasys:ready' }, '*');
}
