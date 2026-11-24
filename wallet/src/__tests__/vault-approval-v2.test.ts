// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { createHash } from 'crypto';

import { checkV2, checkV2Release, isV2, type V2Summary } from '@/services/vault-approval-v2';
import { bindingVaultOp } from '@/services/vault-binding';
import { policyDigest, type VaultIdentity } from '@/services/vault-identity';
import { forgetPublishedReleases } from '@/services/vault-reshare';

const NOW = 1_800_000_000;
const PUBLISHED = '6b516eab16067c519627e6fe26b636da861ccf5722f20ea37ef6559b8925b435'; // vault-v0.39.0

function identity(pubByte: number, mrenclave = PUBLISHED): VaultIdentity {
    const billing = 'b'.repeat(64);
    const pub = Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, pubByte)]);
    const id = createHash('sha256').update('privasys-vault-member-v1\n').update(pub).digest('hex');
    const quote = Buffer.alloc(48 + 384 + 16);
    quote.writeUInt16LE(3, 0);
    Buffer.from(mrenclave, 'hex').copy(quote, 48 + 64);
    createHash('sha256').update(`privasys-vault-identity-v1\n${id}\n${billing}`).digest().copy(quote, 48 + 320);
    return { member_id: id, member_public_key: pub.toString('hex'), billing_id: billing, mrenclave, quote_b64: quote.toString('base64url') };
}

const a = identity(1);
const b = identity(2);

/** A consistent v2 approval, and the challenge it would sign. */
function approval(over: Partial<V2Summary['binding'] & object> = {}, extra: Partial<V2Summary> = {}) {
    const binding = {
        members: [a.member_id, b.member_id],
        op: 'promote',
        handle: 'vaults/x/k',
        target: '09'.repeat(32),
        policy_version: 4,
        approver: 'oidc:0:user-1',
        holder_head: '-',
        nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
        exp: NOW + 120,
        ...over,
    };
    const summary: V2Summary = {
        operation: binding.op,
        handle: binding.handle,
        measurement: binding.target === '-' ? '' : binding.target,
        policy_version: binding.policy_version,
        binding,
        member_identities: [a, b],
        ...extra,
    };
    const vaultOp = bindingVaultOp({
        members: binding.members,
        op: binding.op as any,
        handle: binding.handle,
        target: binding.target === '-' ? undefined : binding.target,
        policyVersion: binding.policy_version,
        approver: binding.approver,
        nonce: binding.nonce,
        exp: binding.exp,
    });
    return { vaultOp, summary };
}

describe('a v2 vault approval', () => {
    it('is told apart from a v1 one', () => {
        expect(isV2({})).toBe(false);
        expect(isV2(approval().summary)).toBe(true);
    });

    it('is accepted when what it shows is what it signs', () => {
        const { vaultOp, summary } = approval();
        expect(checkV2(vaultOp, summary, NOW)).toEqual({
            op: 'promote',
            members: [a.member_id, b.member_id].sort(),
            builds: [PUBLISHED],
            billingIds: ['b'.repeat(64)],
            exp: NOW + 120,
            newPolicy: undefined,
        });
    });

    it('is refused when the challenge is for anything else', () => {
        const { vaultOp, summary } = approval();
        const other = (edit: (s: V2Summary) => void) => {
            const s: V2Summary = JSON.parse(JSON.stringify(summary));
            edit(s);
            return checkV2(vaultOp, s, NOW);
        };
        expect(other((s) => (s.binding!.handle = 'vaults/x/other'))).toBeNull();
        expect(other((s) => (s.binding!.target = '0a'.repeat(32)))).toBeNull();
        expect(other((s) => (s.binding!.members = [a.member_id]))).toBeNull();
        expect(other((s) => (s.binding!.policy_version = 5))).toBeNull();
        expect(other((s) => (s.binding!.op = 'delete'))).toBeNull();
        expect(other((s) => (s.binding!.exp = NOW + 121))).toBeNull();
        expect(checkV2('AAAA', summary, NOW)).toBeNull();
    });

    it('is refused when the card says something the binding does not', () => {
        const { vaultOp, summary } = approval();
        expect(checkV2(vaultOp, { ...summary, handle: 'vaults/x/shown' }, NOW)).toBeNull();
        expect(checkV2(vaultOp, { ...summary, operation: 'export' }, NOW)).toBeNull();
        expect(checkV2(vaultOp, { ...summary, measurement: '0a'.repeat(32) }, NOW)).toBeNull();
        expect(checkV2(vaultOp, { ...summary, policy_version: 9 }, NOW)).toBeNull();
    });

    it('is refused without an identity for every vault named, or once expired', () => {
        const { vaultOp, summary } = approval();
        expect(checkV2(vaultOp, { ...summary, member_identities: [a] }, NOW)).toBeNull();
        expect(checkV2(vaultOp, { ...summary, member_identities: undefined }, NOW)).toBeNull();
        expect(checkV2(vaultOp, summary, NOW + 120)).toBeNull();
    });

    it('is refused when it is not an issuer approval', () => {
        const pinned = approval({ holder_head: 'ab'.repeat(32) });
        expect(checkV2(pinned.vaultOp, pinned.summary, NOW)).toBeNull();
        const holder = approval({ approver: 'cd'.repeat(32) });
        expect(checkV2(holder.vaultOp, holder.summary, NOW)).toBeNull();
    });

    it('binds a policy update to the policy it shows', () => {
        const policy = { operations: [{ ops: ['Sign'] }], version: 2 };
        const good = approval({ op: 'update_policy', target: policyDigest(policy) }, { new_policy: policy });
        expect(checkV2(good.vaultOp, good.summary, NOW)?.newPolicy).toEqual(policy);
        // Another policy than the one bound, none at all, or one on another operation.
        expect(checkV2(good.vaultOp, { ...good.summary, new_policy: { ...policy, version: 3 } }, NOW)).toBeNull();
        expect(checkV2(good.vaultOp, { ...good.summary, new_policy: undefined }, NOW)).toBeNull();
        const promote = approval({}, { new_policy: policy });
        expect(checkV2(promote.vaultOp, promote.summary, NOW)).toBeNull();
    });

    it('accepts an operation that binds nothing more', () => {
        const del = approval({ op: 'delete', target: '-' });
        expect(checkV2(del.vaultOp, del.summary, NOW)?.op).toBe('delete');
    });
});

describe('the vaults\' release', () => {
    beforeEach(() => {
        forgetPublishedReleases();
        (global as any).fetch = jest.fn(async () => ({ ok: false, status: 403 }));
    });

    it('is named when every vault runs one published release', async () => {
        const { vaultOp, summary } = approval();
        const got = await checkV2Release(checkV2(vaultOp, summary, NOW)!);
        expect(got).toEqual({ kind: 'ok', release: expect.objectContaining({ version: 'v0.39.0' }) });
    });

    it('is not, when the vaults differ or GitHub cannot say', async () => {
        const mixed = { op: 'promote' as const, members: [], builds: [PUBLISHED, 'ee'.repeat(32)], billingIds: [], exp: NOW };
        expect((await checkV2Release(mixed)).kind).toBe('unpublished');
        const unknown = { op: 'promote' as const, members: [], builds: ['ee'.repeat(32)], billingIds: [], exp: NOW };
        expect((await checkV2Release(unknown)).kind).toBe('unreachable');
    });
});

describe('a request that leaves its binding out', () => {
    const { checkV1, requiresV2 } = require('@/services/vault-approval-v2');
    const { computeVaultOp } = require('@/services/vault-approval-batch');

    it('is refused for an operation that exists only on v2', () => {
        for (const op of ['update_policy', 'delete', 'delete_after', 'export_assembled', 'issuer_update', 'revoke_pending', 'create']) {
            expect(requiresV2(op)).toBe(true);
        }
        for (const op of ['promote', 'export', 'reshare', 'app-policy', 'policy-update', 'app-recovery']) {
            expect(requiresV2(op)).toBe(false);
        }
    });

    it('is recomputed as v1 when it says what it binds', () => {
        const s = { handle: 'vaults/x/k', measurement: '09'.repeat(32), policy_version: 4, nonce: 'n1', exp: NOW + 60 };
        const vaultOp = computeVaultOp(s.handle, s.measurement, 4, 'n1', NOW + 60);
        expect(checkV1(vaultOp, s, computeVaultOp)).toBe(true);
        expect(checkV1(vaultOp, { ...s, measurement: '0a'.repeat(32) }, computeVaultOp)).toBe(false);
        expect(checkV1(vaultOp, { ...s, handle: 'vaults/x/other' }, computeVaultOp)).toBe(false);
        // One that does not say what it binds is refused, not shown unchecked.
        expect(checkV1(vaultOp, { handle: s.handle, measurement: s.measurement }, computeVaultOp)).toBe(false);
        expect(checkV1(vaultOp, { ...s, nonce: undefined }, computeVaultOp)).toBe(false);
    });

    it('lets the delete of an old key wait for the key that replaces it', () => {
        const { deleteAfterTarget } = require('@/services/vault-binding');
        const target = deleteAfterTarget('apps/x/data-v8', '');
        const good = approval({ op: 'delete_after', handle: 'apps/x/data-v7', target, exp: NOW + 3600 }, { successor_handle: 'apps/x/data-v8' });
        expect(checkV2(good.vaultOp, good.summary, NOW)?.successor).toBe('apps/x/data-v8');
        // Another successor than the one bound, none, itself, or one on another operation.
        expect(checkV2(good.vaultOp, { ...good.summary, successor_handle: 'apps/x/data-v9' }, NOW)).toBeNull();
        expect(checkV2(good.vaultOp, { ...good.summary, successor_handle: undefined }, NOW)).toBeNull();
        const self = approval({ op: 'delete_after', handle: 'apps/x/k', target: deleteAfterTarget('apps/x/k', '') }, { successor_handle: 'apps/x/k' });
        expect(checkV2(self.vaultOp, self.summary, NOW)).toBeNull();
        const promote = approval({}, { successor_handle: 'apps/x/data-v8' });
        expect(checkV2(promote.vaultOp, promote.summary, NOW)).toBeNull();
    });
});
