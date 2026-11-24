// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { createHash } from 'crypto';

import { bindingText, bindingVaultOp, type VaultBinding } from '@/services/vault-binding';

const A = 'aa'.repeat(32);
const B = 'bb'.repeat(32);

const promote: VaultBinding = {
    members: [B, A],
    op: 'promote',
    handle: 'vaults/x/k',
    target: '09'.repeat(32),
    policyVersion: 7,
    approver: 'oidc:0:user-1',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
    exp: 1800000000,
};

describe('vault binding v2', () => {
    it('is the form, members sorted, no trailing newline', () => {
        expect(bindingText(promote)).toBe(
            [
                'privasys-vault-approval/v2',
                '2',
                A,
                B,
                'promote',
                'vaults/x/k',
                '09'.repeat(32),
                '7',
                'oidc:0:user-1',
                '-',
                'AAAAAAAAAAAAAAAAAAAAAA',
                '1800000000',
            ].join('\n'),
        );
    });

    it('writes a missing target as a dash', () => {
        const lines = bindingText({ ...promote, op: 'delete', target: undefined }).split('\n');
        expect(lines[4]).toBe('delete');
        expect(lines[6]).toBe('-');
    });

    it('gives an issuer approval the SHA-256 of the text, base64url', () => {
        const want = createHash('sha256').update(bindingText(promote), 'utf8').digest('base64url');
        expect(bindingVaultOp(promote)).toBe(want);
    });

    it('changes with the constellation, so an approval for one is not one for another', () => {
        expect(bindingVaultOp({ ...promote, members: [A, 'cc'.repeat(32)] })).not.toBe(bindingVaultOp(promote));
    });

    it('refuses what would not be one line each, or is not the form', () => {
        expect(() => bindingText({ ...promote, handle: 'a\nb' })).toThrow();
        expect(() => bindingText({ ...promote, handle: '' })).toThrow();
        expect(() => bindingText({ ...promote, members: [] })).toThrow();
        expect(() => bindingText({ ...promote, members: [A, A] })).toThrow();
        expect(() => bindingText({ ...promote, members: [A.toUpperCase()] })).toThrow();
        expect(() => bindingText({ ...promote, nonce: 'short' })).toThrow();
        expect(() => bindingText({ ...promote, policyVersion: -1 })).toThrow();
        expect(() => bindingText({ ...promote, exp: 1.5 })).toThrow();
        expect(() => bindingText({ ...promote, op: 'sign' as any })).toThrow();
    });
});

describe('the vault\'s own vector', () => {
    // idp/internal/vaultbinding/testdata/v2_vectors.json is the vault's output.
    const v = require('../../../idp/internal/vaultbinding/testdata/v2_vectors.json').binding_v2_update_policy_with_pd;

    it('is reproduced byte for byte', () => {
        const b: VaultBinding = {
            members: v.members,
            op: v.op,
            handle: v.handle,
            target: v.target === '-' ? undefined : v.target,
            policyVersion: v.policy_version,
            approver: v.approver,
            holderHead: v.holder_head === '-' ? undefined : v.holder_head,
            nonce: v.nonce,
            exp: v.exp,
        };
        expect(bindingText(b)).toBe(v.text);
        expect(bindingVaultOp(b)).toBe(v.vault_op);
    });
});
