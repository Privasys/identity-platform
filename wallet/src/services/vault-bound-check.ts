// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The one check of a bound vault approval (binding v2), for a single request
 * and for each entry of a batch. Nothing in a request is believed as sent:
 * the binding is rebuilt from its fields and must be the challenge the passkey
 * would sign, so what is shown is what is signed.
 *
 * No native imports, so all of it runs under test.
 */

import { bindingVaultOp, deleteAfterTarget, updatePolicyFromTarget, VAULT_OPS, type VaultBinding, type VaultOp } from './vault-binding';
import { checkMembers, policyDigest, type VaultIdentity } from './vault-identity';

export interface BoundApproval {
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

/** How long an approval lives at most, at the vault: a delete_after that names
 *  a created successor waits for nothing, so it gets no longer. */
export const APPROVAL_MAX_SECONDS = 600;
/** The margin allowed for clocks when an expiry is compared with this phone's. */
export const CLOCK_MARGIN_SECONDS = 60;

/** One bound approval as it arrives, from a single request or one batch entry. */
export interface BoundRequest {
    operation: string;
    handle: string;
    /** The bound value the request shows; '' or '-' for none. */
    measurement: string;
    policyVersion: number;
    /** A batch entry repeats the binding's nonce; a single request does not. */
    nonce?: string;
    binding: unknown;
    memberIdentities: unknown;
    newPolicy?: unknown;
    currentPolicy?: unknown;
    successorHandle?: unknown;
}

/** Why a bound request is refused: its shape, or a value that disagrees with its binding. */
export type BoundRefusal = 'malformed' | 'entry';

/**
 * The one check of a bound approval, for a single request and for each batch
 * entry: the binding rebuilt from its fields is the challenge the passkey would
 * sign, the request's own fields are the binding's, every vault named has an
 * identity that agrees with itself, a policy change is bound to the policy it
 * shows, and a delete_after that names its successor is bound to it. Expiry
 * against the clock, and what a batch allows beside it, are the callers'.
 */
export function verifyBoundEntry(vaultOp: string, req: BoundRequest): BoundApproval | { refused: BoundRefusal } {
    const malformed = { refused: 'malformed' as const };
    const disagrees = { refused: 'entry' as const };
    const b = (req.binding ?? null) as Record<string, unknown> | null;
    if (!b || typeof b !== 'object') return malformed;
    if (typeof b.op !== 'string' || !(VAULT_OPS as readonly string[]).includes(b.op)) return malformed;
    if (
        typeof b.handle !== 'string' ||
        !Number.isSafeInteger(b.policy_version) ||
        (b.policy_version as number) < 0 ||
        !Number.isSafeInteger(b.exp) ||
        typeof b.nonce !== 'string' ||
        !Array.isArray(b.members)
    ) {
        return malformed;
    }
    // An issuer approval: a holder head belongs to a pinned key, which this
    // card does not sign for.
    if (dash(b.holder_head as string | undefined) !== '-' || !/^oidc:\d+:.+$/.test(String(b.approver))) return malformed;
    const target = dash(b.target as string | undefined) === '-' ? undefined : String(b.target);

    let rebuilt: string;
    try {
        rebuilt = bindingVaultOp({
            members: b.members as string[],
            op: b.op as VaultOp,
            handle: b.handle,
            target,
            policyVersion: b.policy_version as number,
            approver: String(b.approver),
            nonce: b.nonce,
            exp: b.exp as number,
        } satisfies VaultBinding);
    } catch {
        return malformed;
    }
    if (rebuilt !== vaultOp) return disagrees;

    // The request's own fields are the binding's.
    if (req.operation !== b.op || req.handle !== b.handle) return disagrees;
    if (dash(req.measurement) !== dash(target)) return disagrees;
    if (req.policyVersion !== b.policy_version) return disagrees;
    if (req.nonce !== undefined && req.nonce !== b.nonce) return disagrees;

    const members = checkMembers(b.members as string[], req.memberIdentities as VaultIdentity[] | undefined);
    if (!members) return disagrees;

    const hasPolicy = req.newPolicy !== undefined && req.newPolicy !== null;
    const hasCurrent = req.currentPolicy !== undefined && req.currentPolicy !== null;
    try {
        if (b.op === 'update_policy' || b.op === 'create') {
            // Bound to the policy it installs. A key being created has no version yet.
            if (!hasPolicy || hasCurrent) return malformed;
            if (b.op === 'create' && b.policy_version !== 0) return disagrees;
            if (policyDigest(req.newPolicy) !== target) return disagrees;
        } else if (b.op === 'update_policy_from') {
            // Bound to the rules in force and the new ones together, so the
            // change between the two is what is signed.
            if (!hasPolicy || !hasCurrent) return malformed;
            if (updatePolicyFromTarget(policyDigest(req.currentPolicy), policyDigest(req.newPolicy)) !== target) return disagrees;
        } else if (hasPolicy || hasCurrent) {
            return malformed;
        }
    } catch {
        return malformed;
    }

    // A delete_after may name the created key that replaces the old one: the
    // binding's target must then be that successor's.
    let successor: string | undefined;
    const s = req.successorHandle;
    if (s !== undefined && s !== null && s !== '') {
        if (b.op !== 'delete_after' || typeof s !== 'string' || s === b.handle || /\s/.test(s)) return malformed;
        if (deleteAfterTarget(s, '') !== target) return disagrees;
        successor = s;
    }
    return {
        op: b.op as VaultOp,
        members: members.members,
        builds: members.builds,
        billingIds: members.billingIds,
        exp: b.exp as number,
        newPolicy: hasPolicy ? req.newPolicy : undefined,
        ...(hasCurrent ? { currentPolicy: req.currentPolicy } : {}),
        ...(successor ? { successor } : {}),
    };
}
