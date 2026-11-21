// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { p256 } from '@noble/curves/nist.js';

import { deriveHolderKey, holderCommitment, opensCommitment } from '@/services/holder-keys';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// The verifiers test against these same values: change them only together.
const SEED = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const SALT = new Uint8Array(16).map((_, i) => 0xa0 + i);

describe('holder keys', () => {
    it('derives a different, valid P-256 key per verifier', () => {
        const a = deriveHolderKey(SEED, 'attribute');
        const i = deriveHolderKey(SEED, 'identity');
        expect(a.publicKey).toHaveLength(65);
        expect(a.publicKey[0]).toBe(0x04);
        expect(hex(a.publicKey)).not.toEqual(hex(i.publicKey));
        expect(hex(p256.getPublicKey(a.secretKey, false))).toEqual(hex(a.publicKey));
    });

    it('is the same on every device: a function of the seed alone', () => {
        expect(hex(deriveHolderKey(SEED, 'attribute').secretKey)).toEqual(hex(deriveHolderKey(SEED, 'attribute').secretKey));
    });

    it('matches the agreed vectors', () => {
        const a = deriveHolderKey(SEED, 'attribute');
        const i = deriveHolderKey(SEED, 'identity');
        expect({
            attributeScalar: hex(a.secretKey),
            attributePub: hex(a.publicKey),
            identityScalar: hex(i.secretKey),
            identityPub: hex(i.publicKey),
            commitment: holderCommitment(a.publicKey, SALT),
            identityCommitment: holderCommitment(i.publicKey, SALT),
        }).toMatchSnapshot();
        // Recomputed in Go by the Verifiers (crypto/hkdf, crypto/ecdh).
        expect(holderCommitment(i.publicKey, SALT)).toBe('g607rOJG9LvYq7X_ZSPh4MKGazeMIAvXvWW09Bm36hg');
    });

    it('opens its own commitment and no other', () => {
        const { publicKey } = deriveHolderKey(SEED, 'attribute');
        const c = holderCommitment(publicKey, SALT);
        expect(opensCommitment(c, publicKey, SALT)).toBe(true);
        expect(opensCommitment(c, deriveHolderKey(SEED, 'identity').publicKey, SALT)).toBe(false);
        expect(opensCommitment(c, publicKey, new Uint8Array(16))).toBe(false);
    });
});
