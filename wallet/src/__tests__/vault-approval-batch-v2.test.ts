// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { createHash } from 'crypto';

import { computeVaultBatchId, verifyVaultBatch, VaultBatchRefused } from '@/services/vault-approval-batch';
import { bindingVaultOp, deleteAfterTarget } from '@/services/vault-binding';
import { policyDigest, type VaultIdentity } from '@/services/vault-identity';

const BUILD = '47'.repeat(32);
const EXP = 1_800_000_300;

function identity(pubByte: number): VaultIdentity {
    const billing = 'b'.repeat(64);
    const pub = Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, pubByte)]);
    const id = createHash('sha256').update('privasys-vault-member-v1\n').update(pub).digest('hex');
    const quote = Buffer.alloc(48 + 384 + 16);
    quote.writeUInt16LE(3, 0);
    Buffer.from(BUILD, 'hex').copy(quote, 48 + 64);
    createHash('sha256').update(`privasys-vault-identity-v1\n${id}\n${billing}`).digest().copy(quote, 48 + 320);
    return { member_id: id, member_public_key: pub.toString('hex'), billing_id: billing, mrenclave: BUILD, quote_b64: quote.toString('base64url') };
}

const a = identity(1);
const b = identity(2);
const members = [a.member_id, b.member_id];

function entry(op: string, handle: string, target: string, over: Record<string, unknown> = {}, exp = EXP) {
    const nonce = 'AAAAAAAAAAAAAAAAAAAAAA';
    const binding = { members, op, handle, target, policy_version: 3, approver: 'oidc:0:user-1', holder_head: '-', nonce, exp };
    const vault_op = bindingVaultOp({ members, op: op as any, handle, target, policyVersion: 3, approver: binding.approver, nonce, exp });
    return { operation: op, handle, measurement_digest: target, policy_version: 3, nonce, vault_op, binding, ...over };
}

function answer(entries: any[], over: Record<string, unknown> = {}) {
    const batch_id = computeVaultBatchId('Upgrade x', EXP, entries.map((e) => ({ operation: e.operation, vaultOp: e.vault_op })));
    return {
        batch_id,
        label: 'Upgrade x',
        exp: EXP,
        entries,
        member_identities: [a, b],
        options: { publicKey: { challenge: batch_id } },
        ...over,
    };
}

const PROFILE = 'ab'.repeat(32);

describe('delete_after target', () => {
    it('is what privasys.id computes', () => {
        // idp/internal/vaultbinding DeleteAfterTarget, same inputs.
        expect(deleteAfterTarget('apps/x/data-v2', PROFILE)).toBe('4468ea467a88466d002514e22d4af1d114794a8d97ed24694d7e4e39d2057cd5');
        expect(deleteAfterTarget('apps/x/data-v2', '')).toBe('987995df9ada8009cf264cedcede390f35dacee52c74049855eaa2a2a8447727');
    });
});

describe('a batch of v2 entries', () => {
    const promote = entry('promote', 'apps/x/data-v2', PROFILE);
    const del = entry('delete_after', 'apps/x/data-v1', deleteAfterTarget('apps/x/data-v2', PROFILE), {}, EXP + 3300);

    it('is verified: a promote with the old key deleted after it', () => {
        const ans = answer([del, promote]);
        const got = verifyVaultBatch(ans.batch_id, ans);
        expect(got.entries.map((e) => e.operation)).toEqual(['delete_after', 'promote']);
        expect(got.builds).toEqual([BUILD]);
        expect(got.entries[0].v2?.exp).toBe(EXP + 3300);
        expect(got.entries[1].v2?.exp).toBe(EXP);
    });

    it('carries a policy update bound to its policy', () => {
        const policy = { operations: [], version: 2 };
        const upd = entry('update_policy', 'apps/y/k', policyDigest(policy), { new_policy: policy });
        const ans = answer([upd]);
        expect(verifyVaultBatch(ans.batch_id, ans).entries[0].v2?.newPolicy).toEqual(policy);
        const other = answer([{ ...upd, new_policy: { ...policy, version: 3 } }]);
        expect(() => verifyVaultBatch(other.batch_id, other)).toThrow(VaultBatchRefused);
    });

    const refused = (entries: any[], over: Record<string, unknown> = {}) => {
        const ans = answer(entries, over);
        return () => verifyVaultBatch(ans.batch_id, ans);
    };

    it('refuses an old key\'s delete without its successor\'s promote', () => {
        expect(refused([del])).toThrow(VaultBatchRefused);
        const elsewhere = entry('delete_after', 'apps/x/data-v1', 'cd'.repeat(32), {}, EXP + 60);
        expect(refused([elsewhere, promote])).toThrow(VaultBatchRefused);
    });

    it('accepts an old key\'s delete that names a created successor, alone', () => {
        const target = deleteAfterTarget('apps/x/data-v8', '');
        const alone = entry('delete_after', 'apps/x/data-v7', target, { successor_handle: 'apps/x/data-v8' }, EXP);
        const ans = answer([alone]);
        expect(verifyVaultBatch(ans.batch_id, ans).entries[0].v2?.successor).toBe('apps/x/data-v8');
        // Its successor exists already: held for most of an hour, it is refused.
        const held = entry('delete_after', 'apps/x/data-v7', target, { successor_handle: 'apps/x/data-v8' }, EXP + 3300);
        expect(refused([held])).toThrow(VaultBatchRefused);
        expect(refused([{ ...alone, successor_handle: 'apps/x/data-v9' }])).toThrow(VaultBatchRefused);
        expect(refused([{ ...alone, successor_handle: 'apps/x/data-v7' }])).toThrow(VaultBatchRefused);
        expect(refused([{ ...promote, successor_handle: 'apps/x/data-v8' }])).toThrow(VaultBatchRefused);
    });

    it('refuses an entry that outlives the batch, unless it is the old key\'s delete, within a day', () => {
        expect(refused([entry('promote', 'apps/x/data-v2', PROFILE, {}, EXP + 60)])).toThrow(VaultBatchRefused);
        const tooLong = entry('delete_after', 'apps/x/data-v1', deleteAfterTarget('apps/x/data-v2', PROFILE), {}, EXP + 86401);
        expect(refused([tooLong, promote])).toThrow(VaultBatchRefused);
    });

    it('refuses what does not hash, what it cannot place, and a mix of bindings', () => {
        expect(refused([{ ...promote, handle: 'apps/x/other' }])).toThrow(VaultBatchRefused);
        expect(refused([{ ...promote, measurement_digest: 'cd'.repeat(32) }])).toThrow(VaultBatchRefused);
        expect(refused([promote], { member_identities: [a] })).toThrow(VaultBatchRefused);
        expect(refused([promote], { member_identities: undefined })).toThrow(VaultBatchRefused);
        expect(refused([entry('export', 'apps/x/k', PROFILE)])).toThrow(VaultBatchRefused);
        expect(refused([entry('delete', 'apps/x/k', PROFILE)])).toThrow(VaultBatchRefused);
        const { binding: _drop, ...v1 } = entry('promote', 'apps/a/k', PROFILE);
        expect(refused([v1, promote])).toThrow(VaultBatchRefused);
        expect(refused([{ ...promote, binding: { ...promote.binding, holder_head: 'ab'.repeat(32) } }])).toThrow(VaultBatchRefused);
    });
});
