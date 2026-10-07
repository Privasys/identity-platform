// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Silencing one app's notifications, or hearing from it again.
 *
 * privasys.id keeps a row only for the apps a holder silences, as a keyed hash
 * of (identity, app), and drops their notifications at the relay. It has to be
 * done there: on iOS the system shows a push's banner before the wallet runs,
 * so the wallet cannot hide one it has received. A request the holder must
 * answer (an access request) is never silenced, and sign-in and approval
 * pushes do not pass through the app relay at all.
 *
 * Authenticated as the identity this app knows, so the call needs the session
 * from a fresh ceremony with that app's credential, as withdrawing spend
 * consent does.
 */

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

export async function setAppMuted(walletSessionToken: string, appId: string, muted: boolean): Promise<void> {
    const res = await fetch(`${IDP_BASE}/wallet/notify-mutes/${encodeURIComponent(appId)}`, {
        method: muted ? 'PUT' : 'DELETE',
        headers: { Authorization: `Bearer wallet:${walletSessionToken}` },
    });
    if (!res.ok) {
        throw new Error(`the change could not be saved (${res.status})`);
    }
}
