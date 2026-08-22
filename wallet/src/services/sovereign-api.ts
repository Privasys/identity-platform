// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * IdP transport for the sovereign backup blob (services/sovereign.ts).
 * Pure transport, mirroring recovery-api.ts: the blob is opaque
 * ciphertext to the server, authenticated with the wallet session
 * bearer. GET returns null when no blob exists (pre-framework account).
 */

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

function walletHeaders(sessionToken: string): Record<string, string> {
    return { Authorization: `Bearer wallet:${sessionToken}` };
}

/** Store (upsert) the wrapped backup blob. */
export async function putSovereignBackup(walletSessionToken: string, blobB64: string): Promise<void> {
    const res = await fetch(`${IDP_BASE}/recovery/backup`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...walletHeaders(walletSessionToken) },
        body: JSON.stringify({ blob: blobB64 }),
    });
    if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try {
            const body = (await res.json()) as { error?: string };
            if (body.error) msg = body.error;
        } catch {
            /* keep status message */
        }
        throw new Error(`sovereign backup upload failed: ${msg}`);
    }
}

/** Fetch the wrapped backup blob, or null when none is stored. */
export async function getSovereignBackup(walletSessionToken: string): Promise<string | null> {
    const res = await fetch(`${IDP_BASE}/recovery/backup`, {
        method: 'GET',
        headers: walletHeaders(walletSessionToken),
    });
    if (res.status === 404) return null;
    if (!res.ok) {
        throw new Error(`sovereign backup fetch failed: HTTP ${res.status}`);
    }
    const body = (await res.json()) as { blob?: string };
    return body.blob || null;
}
