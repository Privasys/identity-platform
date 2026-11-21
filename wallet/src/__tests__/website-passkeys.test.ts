// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

jest.mock('../../modules/native-keys/src/index', () => ({}));

import { p256 } from '@noble/curves/nist.js';

import { passkeyRoot, syncedPasskeyScalar } from '@/services/website-passkeys';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// The iOS extension and the Android service are checked against these same
// values (.operations website-passkeys plan): change them only together.
const SEED = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const R = new Uint8Array(16).map((_, i) => 0xa0 + i);

describe('website passkeys', () => {
    it('derives the root and a synced passkey per site', () => {
        const root = passkeyRoot(SEED);
        const a = syncedPasskeyScalar(root, R, 'example.com');
        const b = syncedPasskeyScalar(root, R, 'example.org');
        expect(hex(a)).not.toEqual(hex(b));
        expect({
            root: hex(root),
            scalarExampleCom: hex(a),
            pubExampleCom: hex(p256.getPublicKey(a, false)),
        }).toMatchSnapshot();
    });
});
