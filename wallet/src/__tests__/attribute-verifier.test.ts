// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

jest.mock('expo-crypto', () => ({}));
jest.mock('@/services/app-attest', () => ({}));
jest.mock('@/services/attestation', () => ({}));
jest.mock('@/services/encauth', () => ({}));
jest.mock('@/services/wia', () => ({}));
jest.mock('@/stores/profile', () => ({ useProfileStore: { getState: () => ({ profile: null }) } }));
jest.mock('@/stores/settings', () => ({}));
jest.mock('../../modules/native-keys/src/index', () => ({}));
jest.mock('../../modules/native-ratls/src/index', () => ({}));

import { p256 } from '@noble/curves/nist.js';

import { attestMessage, canonicalJson, discloseMessage, materialDigest } from '@/services/attribute-verifier';
import { deriveHolderKey } from '@/services/holder-keys';

// Produced by the Attribute Verifier's own Go code (jose.Canonical and
// server.AttestMessage, Go 1.26) for this material and challenge. What both
// keys sign must be byte for byte what the verifier recomputes.
const MATERIAL = {
    provider: 'google',
    id_token: 'a.b.c',
    note: 'tab\t nl\n bs\b ff\f ls  ps  quote" bs\\ <&> é \u{1F600}',
    nested: { z: 1, a: [true, null, 'x'] },
    reattest: true,
};
const GO_CANONICAL =
    '{"id_token":"a.b.c","nested":{"a":[true,null,"x"],"z":1},' +
    '"note":"tab\\t nl\\n bs\\b ff\\f ls\\u2028 ps\\u2029 quote\\" bs\\\\ <&> é \u{1F600}",' +
    '"provider":"google","reattest":true}';
const GO_MESSAGE =
    '{"challenge":"CHALLENGE","kind":"oidc_id_token","material":"wuibX8TDr1SXc0BGuDCukzWfSr9GzRLJlJ6QzWkbe4M","op":"attest"}';

describe('attribute verifier wire format', () => {
    it('writes canonical JSON exactly as the verifier does', () => {
        expect(canonicalJson(MATERIAL)).toBe(GO_CANONICAL);
    });

    it('builds the attest message the verifier recomputes', () => {
        expect(materialDigest(MATERIAL)).toBe('wuibX8TDr1SXc0BGuDCukzWfSr9GzRLJlJ6QzWkbe4M');
        expect(new TextDecoder().decode(attestMessage('oidc_id_token', MATERIAL, 'CHALLENGE'))).toBe(GO_MESSAGE);
    });

    it('signs the message as raw r||s over its SHA-256, which the verifier checks', () => {
        const { secretKey, publicKey } = deriveHolderKey(
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
            'attribute',
        );
        const msg = attestMessage('oidc_id_token', MATERIAL, 'CHALLENGE');
        const sig = p256.sign(msg, secretKey);
        expect(sig).toHaveLength(64);
        expect(p256.verify(sig, msg, publicKey)).toBe(true);
    });

    it('builds the disclosure message with its fields in order', () => {
        expect(new TextDecoder().decode(discloseMessage('jti-1', 'client-1', 'sub-1', 'n-1', 1700000000))).toBe(
            '{"nonce":"n-1","op":"disclose","proof":"jti-1","rp_id":"client-1","sub":"sub-1","ts":1700000000}',
        );
    });
});
