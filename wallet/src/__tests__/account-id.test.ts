// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The real values from the 2026-09-04 investigation, because the whole point of
 * this helper is that these three spellings name ONE account.
 */

import { accountId, shortAccountId } from '@/utils/account-id';

// Bertrand's canonical meta-account, in each shape the wallet stores it.
const RAW_HEX = '7450432e0d4a3499048896bb8759be4c';
const SUB = 'NzQ1MDQzMmUwZDRhMzQ5OTA0ODg5NmJiODc1OWJlNGM';
const USER_HANDLE = Buffer.from(SUB, 'utf8').toString('base64url');

describe('accountId', () => {
    it('leaves the published account id alone', () => {
        expect(accountId(SUB)).toBe(SUB);
    });

    // The regression: this is what the Credentials screen used to print, and it
    // matches nothing the holder can see anywhere else.
    it('decodes a WebAuthn user handle to the published account id', () => {
        expect(USER_HANDLE.startsWith('TnpRMU1E')).toBe(true);
        expect(accountId(USER_HANDLE)).toBe(SUB);
    });

    it('encodes the legacy raw hex form to the published account id', () => {
        expect(accountId(RAW_HEX)).toBe(SUB);
    });

    it('agrees across all three spellings', () => {
        expect(new Set([accountId(SUB), accountId(USER_HANDLE), accountId(RAW_HEX)]).size).toBe(1);
    });

    // A pairwise account id is base64url of 32 RANDOM bytes, so it decodes to
    // nothing readable and is indistinguishable from a per-app passkey's random
    // handle. Both come back unchanged: that is the correct spelling for the
    // account, and a passkey row shows its rpId rather than an account anyway.
    it('leaves a value that decodes to nothing readable alone', () => {
        const random = Buffer.from(Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + 200) % 256))
            .toString('base64url');
        expect(accountId(random)).toBe(random);
    });

    it('never renders raw bytes as text', () => {
        const random = Buffer.from(Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + 200) % 256))
            .toString('base64url');
        // eslint-disable-next-line no-control-regex
        expect(accountId(random)).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('returns nothing for empty input', () => {
        expect(accountId(undefined)).toBeUndefined();
        expect(accountId('')).toBeUndefined();
        expect(accountId('   ')).toBeUndefined();
    });
});

describe('shortAccountId', () => {
    // The admin account the device turned out NOT to hold. It reads as
    // r2C7Km0L everywhere, and must read as r2C7Km0L here too.
    it('is the prefix the portal and the CLI show', () => {
        const adminSub = 'r2C7Km0Lxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
        expect(shortAccountId(adminSub)).toBe('r2C7Km0L');
        expect(shortAccountId(Buffer.from(adminSub, 'utf8').toString('base64url'))).toBe('r2C7Km0L');
    });

    it('shortens the canonical account to what the portal shows', () => {
        expect(shortAccountId(USER_HANDLE)).toBe(SUB.slice(0, 8));
        expect(shortAccountId(USER_HANDLE)).toBe('NzQ1MDQz');
    });
});
