// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What a key's rules say, as a person can read them.
 *
 * An approval that installs rules binds their digest, and the wallet checks
 * that digest before it shows anything (services/vault-approval-v2). This
 * turns those rules into a few plain facts: who owns the key, who else may
 * approve, which builds can use it, which acts need the owner's approval, and
 * whether it follows platform updates by itself.
 *
 * The facts never claim more than they cover. `uncovered` is the digest of
 * everything in the rules the facts do not speak of: when two sets of rules
 * differ there, the card says other details change and points at the full
 * rules, which are always shown below.
 *
 * Nothing here is trusted input made safe: it reads rules the wallet has
 * already tied to what it signs. A shape it does not know yields fewer facts,
 * never a wrong one.
 */

import { sha256 } from '@noble/hashes/sha2.js';

import { canonicalPolicy } from './vault-identity';

/** How an act on the key is gated for a person. */
export type Gate = 'approval' | 'open' | 'none';

/** The acts on a key a person can be allowed, in the order the card shows them. */
export const PERSON_OPS = ['PromoteProfile', 'UpdatePolicy', 'DeleteKey', 'ExportKey'] as const;
export type PersonOp = (typeof PERSON_OPS)[number];

export interface PolicyFacts {
    /** Who owns the key, e.g. "r2C7Km0L… at privasys.id". Absent when not readable. */
    owner?: string;
    /** Who else may approve (managers), each as the role or person it names. */
    approvers: string[];
    /** The builds that can use the key, each by a short fingerprint. */
    builds: string[];
    /** For each act: needs an approval, open to a person with none, or allowed to no person. */
    gates: Record<PersonOp, Gate>;
    /** Whether the key follows platform runtime updates by itself. */
    followsUpdates: boolean;
    /** For each act: the digest of the exact conditions its person rules carry. */
    conditions: Record<PersonOp, string>;
    /** Digest of everything the facts above do not cover. */
    uncovered: string;
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const digest = (v: unknown) => hex(sha256(new TextEncoder().encode(JSON.stringify(v ?? null))));

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function shorten(s: string): string {
    return s.length > 14 ? `${s.slice(0, 8)}…` : s;
}

function host(issuer: unknown): string {
    try {
        return new URL(String(issuer)).hostname;
    } catch {
        return String(issuer ?? '');
    }
}

/** A person principal as a short label, or undefined when its shape is unknown. */
function person(p: unknown): string | undefined {
    if (!isObject(p)) return undefined;
    const oidc = p.Oidc;
    if (isObject(oidc)) {
        const roles = Array.isArray(oidc.required_roles) ? oidc.required_roles.filter((r) => typeof r === 'string') : [];
        const sub = typeof oidc.sub === 'string' ? oidc.sub : '';
        // A role-only principal names a set of people by their role.
        const who = sub !== '' ? shorten(sub) : (roles as string[]).map((r) => r.split(':').slice(-1)[0]).join(', ');
        return who === '' ? undefined : `${who} · ${host(oidc.issuer)}`;
    }
    const holder = p.Holder;
    if (isObject(holder) && typeof holder.holder_id === 'string') return shorten(holder.holder_id);
    return undefined;
}

/** A build that can use the key: its name when it has one, and a fingerprint of its profile. */
function build(tee: unknown): string {
    const profile = isObject(tee) && isObject(tee.Tee) ? tee.Tee : tee;
    const name = isObject(profile) && typeof profile.name === 'string' && profile.name !== '' ? `${profile.name} ` : '';
    return `${name}${digest(profile).slice(0, 8)}`;
}

/** Whether a rule's principal list names a person (the owner or a manager). */
function namesPerson(principals: unknown): boolean {
    if (!Array.isArray(principals)) return false;
    return principals.some((p) => p === 'Owner' || (isObject(p) && ('Manager' in p || 'Owner' in p)));
}

/** Whether a rule asks for an approval before it lets a person act. */
function asksApproval(requires: unknown): boolean {
    if (!Array.isArray(requires)) return false;
    return requires.some((c) => isObject(c) && ('OidcStepUp' in c || 'HolderApprovals' in c || 'ManagerApproval' in c));
}

/**
 * Read the facts from a key's rules. Throws only on what the vault would
 * refuse too (the rules are not canonicalisable).
 */
export function policyFacts(policy: unknown): PolicyFacts {
    canonicalPolicy(policy);
    const p = policy as Record<string, unknown>;
    const principals = isObject(p.principals) ? p.principals : {};
    const managers = Array.isArray(principals.managers) ? principals.managers : [];
    const tees = Array.isArray(principals.tees) ? principals.tees : [];
    const operations = Array.isArray(p.operations) ? p.operations : [];
    const lifecycle = isObject(p.lifecycle) ? p.lifecycle : {};

    const gates = {} as Record<PersonOp, Gate>;
    const conditions = {} as Record<PersonOp, string>;
    for (const op of PERSON_OPS) {
        let gate: Gate = 'none';
        const exact: unknown[] = [];
        for (const rule of operations) {
            if (!isObject(rule) || !Array.isArray(rule.ops) || !rule.ops.includes(op) || !namesPerson(rule.principals)) continue;
            exact.push([rule.principals, rule.requires ?? []]);
            // One rule that lets a person act with no approval makes the act open.
            if (!asksApproval(rule.requires)) gate = 'open';
            if (gate !== 'open') gate = 'approval';
        }
        gates[op] = gate;
        conditions[op] = digest(exact);
    }

    // Everything the facts do not speak of: the rules with the covered parts
    // taken out. The rules for people are covered by the gates and by
    // `conditions`; the rules for enclaves stay in.
    const rest = {
        ...p,
        principals: { ...principals, owner: undefined, managers: undefined, tees: undefined },
        lifecycle: { ...lifecycle, auto_migrate_to_next_attestation_profile: undefined },
        operations: operations.filter((rule) => !(isObject(rule) && namesPerson(rule.principals))),
    };

    return {
        owner: person(principals.owner),
        approvers: managers.map((m) => person(m) ?? digest(m).slice(0, 8)),
        builds: tees.map(build),
        gates,
        conditions,
        followsUpdates: lifecycle.auto_migrate_to_next_attestation_profile === true,
        uncovered: digest(rest),
    };
}

/** One fact that differs between the rules in force and the new ones. */
export type PolicyChange =
    | { kind: 'owner'; before?: string; after?: string }
    | { kind: 'approvers'; before: string[]; after: string[] }
    | { kind: 'builds'; added: string[]; removed: string[] }
    | { kind: 'gate'; op: PersonOp; before: Gate; after: Gate }
    | { kind: 'followsUpdates'; before: boolean; after: boolean };

export interface PolicyDiff {
    changes: PolicyChange[];
    /** Something the facts do not cover differs too: read the full rules. */
    other: boolean;
}

const sameList = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

/** What changes between the rules in force and the new ones, fact by fact. */
export function policyDiff(current: unknown, next: unknown): PolicyDiff {
    const a = policyFacts(current);
    const b = policyFacts(next);
    const changes: PolicyChange[] = [];
    if (a.owner !== b.owner) changes.push({ kind: 'owner', before: a.owner, after: b.owner });
    if (!sameList(a.approvers, b.approvers)) changes.push({ kind: 'approvers', before: a.approvers, after: b.approvers });
    const added = b.builds.filter((x) => !a.builds.includes(x));
    const removed = a.builds.filter((x) => !b.builds.includes(x));
    if (added.length > 0 || removed.length > 0) changes.push({ kind: 'builds', added, removed });
    // A gate that reads the same but whose exact conditions differ is a change
    // the facts do not show: it counts as "other".
    let conditionsOnly = false;
    for (const op of PERSON_OPS) {
        if (a.gates[op] !== b.gates[op]) changes.push({ kind: 'gate', op, before: a.gates[op], after: b.gates[op] });
        else if (a.conditions[op] !== b.conditions[op]) conditionsOnly = true;
    }
    if (a.followsUpdates !== b.followsUpdates) {
        changes.push({ kind: 'followsUpdates', before: a.followsUpdates, after: b.followsUpdates });
    }
    return { changes, other: conditionsOnly || a.uncovered !== b.uncovered };
}
