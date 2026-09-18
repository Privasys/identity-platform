// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The key to a holder folder.
 *
 * The enclave OS binds a folder to the bytes the wallet sends the first time,
 * and reopens it only for the same bytes. So the properties tested here are not
 * style: a key that changed between two approvals, or between two spellings of
 * the same app id, is a folder of the holder's files that nobody can open.
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

const mockRoot = new Uint8Array(32).map((_, i) => i + 1);
const ROOT = mockRoot;

// The root is the backed-up sovereign root. Here it is a fixed value, so the
// test can say what "the same root after recovery" produces.
jest.mock('@/services/sovereign', () => ({
    ensureDataRoot: jest.fn(async () => mockRoot),
}));

import {
    deriveHolderFolderKey,
    HOLDER_FOLDER_KEY_BYTES,
    holderFolderKeyB64,
    normaliseAppId,
} from '@/services/holder-folder';

const APP = '3f6d1a0e-0000-4000-8000-000000000001';
const OTHER = '0123456789abcdef0123456789abcdef';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

describe('deriveHolderFolderKey', () => {
    it('is exactly the length the enclave OS accepts', () => {
        expect(HOLDER_FOLDER_KEY_BYTES).toBe(64);
        expect(deriveHolderFolderKey(ROOT, APP)).toHaveLength(64);
    });

    // After an enclave restart, or a revoke and a fresh approval, the folder
    // reopens only if the wallet sends what it sent the first time.
    it('gives the same bytes for the same app every time', () => {
        expect(hex(deriveHolderFolderKey(ROOT, APP))).toBe(hex(deriveHolderFolderKey(ROOT, APP)));
    });

    // The attested id arrives dashed; other paths carry it bare. A key that
    // depended on the spelling would open a different folder for the same app.
    it('does not depend on how the app id is spelt', () => {
        const dashed = deriveHolderFolderKey(ROOT, APP);
        const bare = deriveHolderFolderKey(ROOT, APP.replace(/-/g, ''));
        const upper = deriveHolderFolderKey(ROOT, APP.toUpperCase());
        expect(hex(bare)).toBe(hex(dashed));
        expect(hex(upper)).toBe(hex(dashed));
    });

    // One app must never be able to open another's folder.
    it('differs between apps', () => {
        expect(hex(deriveHolderFolderKey(ROOT, APP))).not.toBe(hex(deriveHolderFolderKey(ROOT, OTHER)));
    });

    // What recovery gives back is the root, so a different root is a different
    // holder, and must not produce this holder's keys.
    it('differs between roots', () => {
        const otherRoot = new Uint8Array(32).fill(7);
        expect(hex(deriveHolderFolderKey(otherRoot, APP))).not.toBe(hex(deriveHolderFolderKey(ROOT, APP)));
    });

    // Domain separation from the per-app data key W, derived from the same
    // root: the folder key must not be one an app could also be handed as W.
    it('is independent of the per-app data key derived from the same root', () => {
        const wStyle = hkdf(sha256, ROOT, undefined, new TextEncoder().encode('privasys-sovereign/w/v1'), 64);
        expect(hex(deriveHolderFolderKey(ROOT, APP))).not.toBe(hex(wStyle));
    });

    it.each(['', 'not-an-app', 'app:3f6d1a0e000040008000000000000001', '3f6d1a0e'])(
        'refuses %p as an app id',
        (bad) => {
            expect(() => deriveHolderFolderKey(ROOT, bad)).toThrow(/not an app id/);
        },
    );
});

describe('normaliseAppId', () => {
    it('reduces every spelling to 32 lowercase hex', () => {
        expect(normaliseAppId(APP)).toBe('3f6d1a0e000040008000000000000001');
        expect(normaliseAppId(` ${APP.toUpperCase()} `)).toBe('3f6d1a0e000040008000000000000001');
    });
});

describe('holderFolderKeyB64', () => {
    // Standard base64, because that is what the mint's key_b64 is decoded with.
    it('is standard base64 of the 64 derived bytes', async () => {
        const b64 = await holderFolderKeyB64(APP);
        expect(b64).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
        const decoded = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
        expect(decoded).toHaveLength(64);
        expect(hex(decoded)).toBe(hex(deriveHolderFolderKey(ROOT, APP)));
    });
});
