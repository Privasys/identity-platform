// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { createHash } from 'crypto';

import { canonicalPolicy, checkIdentity, checkMembers, memberId, policyDigest, type VaultIdentity } from '@/services/vault-identity';

// The vault's own output (idp/internal/vaultbinding/testdata/v2_vectors.json).
const vectors = require('../../../idp/internal/vaultbinding/testdata/v2_vectors.json');

/** An identity that agrees with itself: a v3 SGX quote carrying it. */
function identity(pubByte: number, billing = 'b'.repeat(64), mrenclave = '47'.repeat(32)): VaultIdentity {
    const pub = Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, pubByte)]);
    const id = createHash('sha256').update('privasys-vault-member-v1\n').update(pub).digest('hex');
    const quote = Buffer.alloc(48 + 384 + 16);
    quote.writeUInt16LE(3, 0);
    Buffer.from(mrenclave, 'hex').copy(quote, 48 + 64);
    createHash('sha256').update(`privasys-vault-identity-v1\n${id}\n${billing}`).digest().copy(quote, 48 + 320);
    return {
        member_id: id,
        member_public_key: pub.toString('hex'),
        billing_id: billing,
        mrenclave,
        quote_b64: quote.toString('base64url'),
    };
}

describe('the vault\'s vectors', () => {
    it('member id', () => {
        expect(memberId(vectors.member_id.public_key_sec1_hex)).toBe(vectors.member_id.member_id);
    });

    it('policy digest over the policy as sent', () => {
        const policy = JSON.parse(vectors.policy_digest.policy_as_sent);
        expect(canonicalPolicy(policy)).toBe(vectors.policy_digest.jcs);
        expect(policyDigest(policy)).toBe(vectors.policy_digest.pd);
    });
});

describe('a vault identity', () => {
    it('is accepted when it agrees with itself, and gives its build', () => {
        expect(checkIdentity(identity(1))).toBe('47'.repeat(32));
    });

    it('is refused when any part disagrees', () => {
        const ok = identity(1);
        expect(checkIdentity({ ...ok, member_id: identity(2).member_id })).toBeNull();
        expect(checkIdentity({ ...ok, billing_id: 'c'.repeat(64) })).toBeNull();
        expect(checkIdentity({ ...ok, mrenclave: '48'.repeat(32) })).toBeNull();
        expect(checkIdentity({ ...ok, quote_b64: 'AAAA' })).toBeNull();
        expect(checkIdentity({ ...ok, member_public_key: '04' })).toBeNull();
        // A TDX quote (TEE type 0x81) is not a vault's.
        const tdx = Buffer.from(ok.quote_b64, 'base64url');
        tdx.writeUInt32LE(0x81, 4);
        expect(checkIdentity({ ...ok, quote_b64: tdx.toString('base64url') })).toBeNull();
    });

    it('covers every member named, or the approval is not approvable', () => {
        const a = identity(1);
        const b = identity(2);
        const got = checkMembers([b.member_id, a.member_id], [a, b]);
        expect(got?.members).toEqual([a.member_id, b.member_id].sort());
        expect(got?.builds).toEqual(['47'.repeat(32)]);
        expect(checkMembers([a.member_id, b.member_id], [a])).toBeNull();
        expect(checkMembers([a.member_id, a.member_id], [a])).toBeNull();
        expect(checkMembers([a.member_id], [a, { ...b, billing_id: 'x' }])).toBeNull();
        expect(checkMembers([], [a])).toBeNull();
        expect(checkMembers([a.member_id], undefined)).toBeNull();
    });

    it('reports two builds when the members do not run the same one', () => {
        const a = identity(1);
        const b = identity(2, 'b'.repeat(64), '99'.repeat(32));
        expect(checkMembers([a.member_id, b.member_id], [a, b])?.builds).toEqual(['47'.repeat(32), '99'.repeat(32)]);
    });
});

describe('policy digest', () => {
    it('sorts member names and ignores how the policy was written', () => {
        expect(canonicalPolicy({ b: 1, a: [true, null, 'x'] })).toBe('{"a":[true,null,"x"],"b":1}');
        expect(policyDigest({ b: 1, a: 2 })).toBe(policyDigest({ a: 2, b: 1 }));
    });

    it('refuses what the vault refuses', () => {
        expect(() => policyDigest({ a: 1.5 })).toThrow();
        expect(() => policyDigest({ a: 2 ** 60 })).toThrow();
        expect(() => policyDigest({ é: 1 })).toThrow();
        expect(() => policyDigest({ a: '\ud800' })).toThrow();
        expect(() => policyDigest({ a: '�' })).toThrow();
        expect(() => policyDigest([1])).toThrow();
        expect(() => policyDigest(null)).toThrow();
    });
});
