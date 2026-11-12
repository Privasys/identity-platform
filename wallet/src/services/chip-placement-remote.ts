// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The chip-placement list, kept current without a release.
 *
 * The wallet ships a list (services/chip-placement.ts). privasys.id serves a
 * signed copy that may be newer; this fetches it, checks it, and keeps it for
 * next time. The newest of the two is the one used.
 *
 * Signed the way the version floor is, by the same publisher key, and opened
 * with the same check (services/app-version.ts). Serving privasys.id is not
 * enough to change where a holder is told to put their phone. A different
 * signed document served at this address is refused by its schema.
 *
 * What is kept on the phone is the signed envelope, not the list read out of
 * it, and it is checked again on every read: a check that only ran at download
 * would be one file write away from no check.
 */

import { Directory, File, Paths } from 'expo-file-system';

import { openEnvelope } from '@/services/app-version';
import { BUILT_IN_PLACEMENT, parsePlacementDoc, type PlacementDoc } from '@/services/chip-placement';
import { withTimeout } from '@/utils/timeout';

const IDP_BASE_URL = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

export const PLACEMENT_URL = `${IDP_BASE_URL}/wallet/chip-placement.json`;

const FETCH_TIMEOUT_MS = 8_000;

/** A list dated further ahead than this is refused: it could never be replaced. */
const MAX_AHEAD_MS = 24 * 60 * 60 * 1000;

const cacheFile = () => new File(new Directory(Paths.document, 'chip-placement'), 'placement.json');

/** Open a signed envelope and read the list out of it, or null. */
export function openPlacement(envelopeText: string, now: number = Date.now()): PlacementDoc | null {
    try {
        const text = openEnvelope(JSON.parse(envelopeText));
        if (!text) return null;
        const doc = parsePlacementDoc(JSON.parse(text));
        if (!doc) return null;
        if (Date.parse(doc.issuedAt) > now + MAX_AHEAD_MS) return null;
        return doc;
    } catch {
        return null;
    }
}

/** The newer of two lists. */
export function newest(a: PlacementDoc, b: PlacementDoc | null): PlacementDoc {
    return b && Date.parse(b.issuedAt) > Date.parse(a.issuedAt) ? b : a;
}

function readCached(): PlacementDoc | null {
    try {
        const file = cacheFile();
        if (!file.exists) return null;
        return openPlacement(file.textSync());
    } catch {
        return null;
    }
}

/** The list to use now: the one in the build, or a newer one kept from before. */
export function currentPlacement(): PlacementDoc {
    return newest(BUILT_IN_PLACEMENT, readCached());
}

/**
 * Ask privasys.id for a newer list and keep it. Returns the list to use.
 *
 * Never throws and never waits long: guidance on where to lay a phone is not
 * worth holding an identity check up for.
 */
export async function refreshPlacement(): Promise<PlacementDoc> {
    const current = currentPlacement();
    try {
        // No credentials: asking for this list must not be tied to a session.
        const res = await withTimeout(fetch(PLACEMENT_URL, { credentials: 'omit' }), FETCH_TIMEOUT_MS, 'chip placement');
        if (!res.ok) return current;
        const text = await res.text();
        const fetched = openPlacement(text);
        if (!fetched || newest(current, fetched) !== fetched) return current;
        try {
            const file = cacheFile();
            if (!file.parentDirectory.exists) file.parentDirectory.create({ intermediates: true });
            if (file.exists) file.delete();
            file.create();
            file.write(text);
        } catch {
            // Not kept: it is fetched again next time.
        }
        return fetched;
    } catch (e) {
        console.warn('[KYC] could not refresh the chip placement list:', e instanceof Error ? e.message : e);
        return current;
    }
}
