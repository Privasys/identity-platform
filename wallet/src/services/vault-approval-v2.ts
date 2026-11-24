// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A vault approval on binding v2, checked before it is shown.
 *
 * The request arrives through privasys.id with the fields of the binding, the
 * identities of the vaults it names and, for a policy update, the new policy.
 * Nothing in it is believed as sent. The wallet:
 *
 *   1. rebuilds the binding's text from those fields and checks its digest is
 *      the challenge the passkey would sign (so what is shown is what is
 *      signed);
 *   2. checks the card's own fields (operation, key, bound value, policy
 *      version) are the binding's;
 *   3. checks every vault named has an identity that agrees with itself
 *      (services/vault-identity);
 *   4. for a policy update, checks the binding's target is the digest of the
 *      policy it would show;
 *   5. refuses a binding that has expired.
 *
 * `checkV2` is the synchronous part. `checkV2Release` then names the vaults'
 * build as a published Enclave Vault release, from GitHub.
 */

import { bindingVaultOp, VAULT_OPS, type VaultBinding, type VaultOp } from './vault-binding';
import { checkMembers, policyDigest, type VaultIdentity } from './vault-identity';
import { vaultReleaseFor, type VaultRelease } from './vault-reshare';

/** The binding's fields, as privasys.id relays them. */
export interface BindingFields {
    members: string[];
    op: string;
    handle: string;
    target: string;
    policy_version: number;
    approver: string;
    holder_head: string;
    nonce: string;
    exp: number;
}

/** What a v2 approval carries, beside the v1 summary fields. */
export interface V2Summary {
    operation: string;
    handle: string;
    measurement: string;
    policy_version?: number;
    binding?: BindingFields;
    member_identities?: VaultIdentity[];
    new_policy?: unknown;
}

export interface CheckedV2 {
    op: VaultOp;
    /** The vaults the approval is for, sorted member ids. */
    members: string[];
    /** The builds those vaults claim (one, unless they differ). */
    builds: string[];
    /** Unix seconds: the approval is good until then. */
    exp: number;
    /** The new policy, for a policy update. */
    newPolicy?: unknown;
}

const dash = (s: string | undefined) => (s === undefined || s === '' ? '-' : s);

/** Whether a pending approval is a v2 one. */
export function isV2(summary: { binding?: unknown }): boolean {
    return summary.binding !== undefined && summary.binding !== null;
}

/**
 * Check a v2 approval against the challenge it would sign. Null when anything
 * is missing or disagrees: the card then offers only Decline.
 */
export function checkV2(vaultOp: string, summary: V2Summary, nowSeconds: number): CheckedV2 | null {
    const b = summary.binding;
    if (!b || typeof b !== 'object') return null;
    if (!(VAULT_OPS as readonly string[]).includes(b.op)) return null;
    if (!Number.isSafeInteger(b.exp) || b.exp <= nowSeconds) return null;
    // An issuer approval: a holder head belongs to a pinned key, which this
    // card does not sign for.
    if (dash(b.holder_head) !== '-' || !/^oidc:\d+:.+$/.test(String(b.approver))) return null;

    const binding: VaultBinding = {
        members: b.members,
        op: b.op as VaultOp,
        handle: b.handle,
        target: dash(b.target) === '-' ? undefined : b.target,
        policyVersion: b.policy_version,
        approver: b.approver,
        nonce: b.nonce,
        exp: b.exp,
    };
    let rebuilt: string;
    try {
        rebuilt = bindingVaultOp(binding);
    } catch {
        return null;
    }
    if (rebuilt !== vaultOp) return null;

    // The card's own fields are the binding's.
    if (summary.operation !== b.op || summary.handle !== b.handle) return null;
    if (dash(summary.measurement) !== dash(b.target)) return null;
    if ((summary.policy_version ?? 0) !== b.policy_version) return null;

    const members = checkMembers(b.members, summary.member_identities);
    if (!members) return null;

    const hasPolicy = summary.new_policy !== undefined && summary.new_policy !== null;
    if (b.op === 'update_policy') {
        if (!hasPolicy) return null;
        try {
            if (policyDigest(summary.new_policy) !== b.target) return null;
        } catch {
            return null;
        }
    } else if (hasPolicy) {
        return null;
    }
    return {
        op: b.op as VaultOp,
        members: members.members,
        builds: members.builds,
        exp: b.exp,
        newPolicy: hasPolicy ? summary.new_policy : undefined,
    };
}

export type V2Release =
    /** Every vault runs this published release. */
    | { kind: 'ok'; release: VaultRelease }
    /** The vaults do not all claim one build, or it is no published release. */
    | { kind: 'unpublished'; build: string }
    /** GitHub could not be reached. */
    | { kind: 'unreachable' };

/** Name the vaults' build as a published Enclave Vault release. */
export async function checkV2Release(checked: CheckedV2): Promise<V2Release> {
    if (checked.builds.length !== 1) return { kind: 'unpublished', build: checked.builds.join(', ') };
    try {
        const release = await vaultReleaseFor(checked.builds[0]);
        return release ? { kind: 'ok', release } : { kind: 'unpublished', build: checked.builds[0] };
    } catch {
        return { kind: 'unreachable' };
    }
}
