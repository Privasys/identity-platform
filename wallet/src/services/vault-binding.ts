// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The text a vault approval binds (binding v2), built here from what the
 * approval screen shows, never taken from whoever relays the request.
 *
 *   privasys-vault-approval/v2
 *   <member count>
 *   <member_id>            one line each, sorted
 *   <op>
 *   <handle>
 *   <target>
 *   <policy_version>
 *   <approver>
 *   <holder_head>
 *   <nonce>
 *   <exp>
 *
 * UTF-8, lines joined by "\n", no trailing newline. A missing value is "-".
 * The members are the vaults the approval is for: a vault refuses a binding
 * that does not name it, which is what keeps an approval made for one
 * constellation from being presented to another (dev and production
 * included).
 *
 * An approval through an issuer carries base64url(SHA-256(text)) as its
 * `vault_op`. A phone's own approval key signs the text itself.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToBase64url } from '@/utils/encoding';

export const BINDING_DOMAIN = 'privasys-vault-approval/v2';

export const VAULT_OPS = [
    'create',
    'promote',
    'export',
    'export_assembled',
    'issuer_create',
    'issuer_update',
    'issuer_delete',
    'update_policy',
    'delete',
    'reshare',
    'revoke_pending',
    'delete_after',
    'update_policy_from',
] as const;
export type VaultOp = (typeof VAULT_OPS)[number];

export interface VaultBinding {
    /** The member ids of the vaults this approval is for (64 lowercase hex each). */
    members: string[];
    op: VaultOp;
    handle: string;
    /** What the operation is bound to, or absent when it binds nothing more. */
    target?: string;
    policyVersion: number;
    /** The holder id, or `oidc:<issuer index>:<sub>` for an issuer approval. */
    approver: string;
    /** The holder record statement the phone's state was at; absent for an issuer approval. */
    holderHead?: string;
    /** 16 random bytes, base64url. */
    nonce: string;
    /** Unix seconds. */
    exp: number;
}

const MEMBER_ID = /^[0-9a-f]{64}$/;
const NONCE = /^[A-Za-z0-9_-]{22}$/;

function line(name: string, value: string): string {
    if (value === '' || /[\n\r]/.test(value)) throw new Error(`vault binding: ${name} is empty or has a line break`);
    return value;
}

function integer(name: string, n: number): string {
    if (!Number.isSafeInteger(n) || n < 0) throw new Error(`vault binding: ${name} is not a whole number`);
    return String(n);
}

/** The binding's text. Throws on anything that would not be one line, or is not what the form allows. */
export function bindingText(b: VaultBinding): string {
    if (!VAULT_OPS.includes(b.op)) throw new Error('vault binding: unknown operation');
    const members = [...new Set(b.members)].sort();
    if (members.length === 0 || members.length !== b.members.length || members.some((m) => !MEMBER_ID.test(m))) {
        throw new Error('vault binding: members must be distinct member ids');
    }
    if (!NONCE.test(b.nonce)) throw new Error('vault binding: nonce is not 16 bytes of base64url');
    return [
        BINDING_DOMAIN,
        String(members.length),
        ...members,
        b.op,
        line('handle', b.handle),
        line('target', b.target ?? '-'),
        integer('policy version', b.policyVersion),
        line('approver', b.approver),
        line('holder head', b.holderHead ?? '-'),
        b.nonce,
        integer('expiry', b.exp),
    ].join('\n');
}

/** What an issuer approval carries as `vault_op`: base64url(SHA-256(text)). */
export function bindingVaultOp(b: VaultBinding): string {
    return bytesToBase64url(sha256(new TextEncoder().encode(bindingText(b))));
}

/**
 * The target of a delete_after: the old key may be deleted only after this
 * successor, and only after that promote. hex SHA-256 of
 * "privasys-delete-after-v1\n" successor handle "\n" its promote target.
 */
export function deleteAfterTarget(successorHandle: string, successorTarget: string): string {
    const text = `privasys-delete-after-v1\n${successorHandle}\n${successorTarget === '' ? '-' : successorTarget}`;
    return Array.from(sha256(new TextEncoder().encode(text)), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * The target of an update_policy_from: the rules in force and the new ones,
 * bound together. hex SHA-256 of "privasys-update-policy-from-v1\n"
 * PD(current) "\n" PD(new), each PD 64 lowercase hex digits.
 */
export function updatePolicyFromTarget(currentPd: string, newPd: string): string {
    if (!/^[0-9a-f]{64}$/.test(currentPd) || !/^[0-9a-f]{64}$/.test(newPd)) {
        throw new Error('vault binding: a policy digest is not 64 lowercase hex digits');
    }
    const text = `privasys-update-policy-from-v1\n${currentPd}\n${newPd}`;
    return Array.from(sha256(new TextEncoder().encode(text)), (b) => b.toString(16).padStart(2, '0')).join('');
}
