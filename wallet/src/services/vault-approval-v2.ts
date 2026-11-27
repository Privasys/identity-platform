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

import { bindingVaultOp, deleteAfterTarget, updatePolicyFromTarget, VAULT_OPS, type VaultBinding, type VaultOp } from './vault-binding';
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
    /** update_policy_from: the rules in force, as the vault returns them. */
    current_policy?: unknown;
    /** A delete_after for a created successor: the key the old one waits for. */
    successor_handle?: string;
    /** The vaults' release tag, as a hint for the lookup. Bound by nothing. */
    vault_release?: string;
}

export interface CheckedV2 {
    op: VaultOp;
    /** The vaults the approval is for, sorted member ids. */
    members: string[];
    /** The builds those vaults claim (one, unless they differ). */
    builds: string[];
    /** Their billing ids (one, unless they differ): which platform they are on. */
    billingIds: string[];
    /** Unix seconds: the approval is good until then. */
    exp: number;
    /** The new policy, for a policy update or a creation. */
    newPolicy?: unknown;
    /** The rules in force, when the approval binds them too: what changes can then be shown. */
    currentPolicy?: unknown;
    /** For the delete of an old key: the key that replaces it. */
    successor?: string;
}

const dash = (s: string | undefined) => (s === undefined || s === '' ? '-' : s);

/** Whether a pending approval is a v2 one. */
export function isV2(summary: { binding?: unknown }): boolean {
    return summary.binding !== undefined && summary.binding !== null;
}

/**
 * Operations that exist only on binding v2. A request for one that carries no
 * binding is not an older, unchecked form of it: it is refused. Otherwise
 * leaving the binding out would be a way past every check here.
 */
const V2_ONLY = new Set<string>(VAULT_OPS.filter((op) => op !== 'promote' && op !== 'export' && op !== 'reshare'));

export function requiresV2(operation: string): boolean {
    return V2_ONLY.has(operation);
}

/**
 * A v1 approval that says what it binds (its nonce and expiry) is recomputed
 * too: the challenge must be the v1 binding of what the card shows. One that
 * does not say (an older privasys.id) is shown as before.
 */
export function checkV1(
    vaultOp: string,
    summary: { handle: string; measurement: string; policy_version?: number; nonce?: string; exp?: number },
    v1Binding: (handle: string, measurement: string, policyVersion: number, nonce: string, exp: number) => string,
): boolean {
    // privasys.id says what every v1 approval binds. One that does not is not
    // an older form: it is refused.
    if (typeof summary.nonce !== 'string' || !Number.isSafeInteger(summary.exp)) return false;
    return v1Binding(summary.handle, summary.measurement ?? '', summary.policy_version ?? 0, summary.nonce, summary.exp as number) === vaultOp;
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
    const hasCurrent = summary.current_policy !== undefined && summary.current_policy !== null;
    if (b.op === 'update_policy' || b.op === 'create') {
        // Bound to the policy it installs. A key being created has no version yet.
        if (!hasPolicy || hasCurrent) return null;
        if (b.op === 'create' && b.policy_version !== 0) return null;
        try {
            if (policyDigest(summary.new_policy) !== b.target) return null;
        } catch {
            return null;
        }
    } else if (b.op === 'update_policy_from') {
        // Bound to the rules in force and the new ones together, so the
        // change between the two is what is signed.
        if (!hasPolicy || !hasCurrent) return null;
        try {
            const want = updatePolicyFromTarget(policyDigest(summary.current_policy), policyDigest(summary.new_policy));
            if (want !== b.target) return null;
        } catch {
            return null;
        }
    } else if (hasPolicy || hasCurrent) {
        return null;
    }
    // The delete of an old key waits for the key that replaces it: the
    // binding's target must be that of the successor the card names.
    let successor: string | undefined;
    if (b.op === 'delete_after') {
        const s = summary.successor_handle;
        if (typeof s !== 'string' || s === '' || s === b.handle || /[\n\r]/.test(s)) return null;
        if (deleteAfterTarget(s, '') !== b.target) return null;
        // That key exists already, so this approval waits for nothing: it
        // lives no longer than any other (the vault's limit, with a margin
        // for clocks).
        if (b.exp > nowSeconds + 600 + 60) return null;
        successor = s;
    } else if (summary.successor_handle) {
        return null;
    }
    return {
        op: b.op as VaultOp,
        members: members.members,
        builds: members.builds,
        billingIds: members.billingIds,
        exp: b.exp,
        newPolicy: hasPolicy ? summary.new_policy : undefined,
        ...(hasCurrent ? { currentPolicy: summary.current_policy } : {}),
        ...(successor ? { successor } : {}),
    };
}

export type V2Release =
    /** Every vault runs this published release. */
    | { kind: 'ok'; release: VaultRelease }
    /** The vaults do not all claim one build, or it is no published release. */
    | { kind: 'unpublished'; build: string }
    /** GitHub could not be reached. */
    | { kind: 'unreachable' }
    /** A rule change that leaves out the rules it replaces, on vaults that can bind them. */
    | { kind: 'mismatch' };

/**
 * Whether a release binds a rule change to the rules it replaces
 * (`update_policy_from`): v0.42.0 and every release after it. The version is
 * that of a release the vaults' own quotes were matched to, so it is not a
 * claim of whoever relays the request.
 *
 * vault-v0.42.0 is the first release that carries it: it builds enclave-os-mini
 * 0b67549, which contains 1508ec0 (update_policy_from); vault-v0.41.0 builds
 * 463f005, which does not.
 */
export function bindsReplacedRules(version: string): boolean {
    const m = /^v(\d+)\.(\d+)\.(\d+)$/.exec(version);
    if (!m) return false;
    const [major, minor] = [Number(m[1]), Number(m[2])];
    return major > 0 || minor >= 42;
}

/**
 * Whether an operation is refused on vaults running `version`: a rule change
 * that leaves out the rules it replaces, where the vaults can bind them, since
 * the card could not show what changes. The one rule for a single approval
 * and for every entry of a batch.
 */
export function refusedOnRelease(op: string, version: string): boolean {
    return op === 'update_policy' && bindsReplacedRules(version);
}

/**
 * Name the vaults' build as a published Enclave Vault release. `hint` is a
 * release tag relayed with the request: it says where to look first, and
 * GitHub's answer is what counts.
 */
export async function checkV2Release(checked: CheckedV2, hint?: string): Promise<V2Release> {
    if (checked.builds.length !== 1) return { kind: 'unpublished', build: checked.builds.join(', ') };
    try {
        const release = await vaultReleaseFor(checked.builds[0], hint);
        if (!release) return { kind: 'unpublished', build: checked.builds[0] };
        // On vaults that can bind the rules being replaced, a rule change that
        // leaves them out is not signed: the card could not show what changes.
        if (refusedOnRelease(checked.op, release.version)) return { kind: 'mismatch' };
        return { kind: 'ok', release };
    } catch {
        return { kind: 'unreachable' };
    }
}
