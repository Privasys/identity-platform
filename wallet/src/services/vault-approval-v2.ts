// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A vault approval on binding v2, checked before it is shown.
 *
 * The request arrives through privasys.id with the fields of the binding, the
 * identities of the vaults it names and, for a policy change, the policies.
 * `checkV2` runs the check every bound approval gets (services/vault-bound-check)
 * and refuses one that has expired. `releaseVerdict` then names the vaults'
 * build as a published Enclave Vault release, from GitHub.
 */

import { APPROVAL_MAX_SECONDS, CLOCK_MARGIN_SECONDS, verifyBoundEntry, type BoundApproval } from './vault-bound-check';
import { VAULT_OPS } from './vault-binding';
import type { VaultIdentity } from './vault-identity';
import { billingPlatform, type BillingPlatform } from './platforms';
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
 * Check a single v2 approval against the challenge it would sign. Null when
 * anything is missing or disagrees: the card then offers only Decline.
 */
export function checkV2(vaultOp: string, summary: V2Summary, nowSeconds: number): BoundApproval | null {
    const checked = verifyBoundEntry(vaultOp, {
        operation: summary.operation,
        handle: summary.handle,
        measurement: summary.measurement,
        policyVersion: summary.policy_version ?? 0,
        binding: summary.binding,
        memberIdentities: summary.member_identities,
        newPolicy: summary.new_policy,
        currentPolicy: summary.current_policy,
        successorHandle: summary.successor_handle,
    });
    if ('refused' in checked) return null;
    if (checked.exp <= nowSeconds) return null;
    if (checked.op === 'delete_after') {
        // Alone, the delete of an old key names the created key that replaces
        // it. That key exists already, so the approval waits for nothing and
        // lives no longer than any other.
        if (!checked.successor) return null;
        if (checked.exp > nowSeconds + APPROVAL_MAX_SECONDS + CLOCK_MARGIN_SECONDS) return null;
    }
    return checked;
}

/** What the wallet says of the vaults an approval is for, before Approve is offered. */
export type ReleaseVerdict =
    /** Every vault runs this published release, on this platform when asked. */
    | { kind: 'ok'; release: VaultRelease; platform?: BillingPlatform }
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
 * The one release verdict, for a single approval, a key renewal and a batch:
 * the vaults' build named as a published Enclave Vault release, none of `ops`
 * refused on it, and, given their billing ids, the platform they are on.
 * `hint` is a release tag relayed with the request: it says where to look
 * first, and GitHub's answer is what counts.
 */
export async function releaseVerdict(
    builds: readonly string[],
    ops: readonly string[],
    opts: { hint?: string; billingIds?: readonly string[] } = {},
): Promise<ReleaseVerdict> {
    if (builds.length !== 1) return { kind: 'unpublished', build: builds.join(', ') };
    let release: VaultRelease | null;
    try {
        release = await vaultReleaseFor(builds[0], opts.hint);
    } catch {
        return { kind: 'unreachable' };
    }
    if (!release) return { kind: 'unpublished', build: builds[0] };
    // On vaults that can bind the rules being replaced, a rule change that
    // leaves them out is not signed: the card could not show what changes.
    const version = release.version;
    if (ops.some((op) => refusedOnRelease(op, version))) return { kind: 'mismatch' };
    if (!opts.billingIds) return { kind: 'ok', release };
    return { kind: 'ok', release, platform: await billingPlatform([...opts.billingIds]) };
}
