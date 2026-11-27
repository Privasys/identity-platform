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
 *
 * The same rules reach the wallet written two ways. A vault returns them with
 * every default written out (`"requires": []`, `"auditors": []`,
 * `"pinned_spki_sha256_hex": null`); a caller may leave those out. The
 * approval binds each as it was sent, and that is checked elsewhere. Here the
 * two are compared by what they say, so rules that say the same thing never
 * show as a change (they did, on the first cards: every build that stayed was
 * listed as removed and added again, 2026-11-25).
 *
 * Only the fields named below are read that way. Everywhere else an empty
 * value is kept as sent, because it can mean something: a build's
 * `acceptable_tcb_statuses` is the case that matters. Absent or null, the
 * vault checks no patch level; an empty list is the strictest check there is.
 * Reading the two as one would show a key being weakened as no change at all.
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
    /** The builds that can use the key, each by a short label, for display. */
    builds: string[];
    /** What each build above IS, in full: never the label, which is short. */
    buildIds: string[];
    /** For each build's identity: the digest of everything its entry says. */
    buildDetails: Record<string, string>;
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

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Lists a vault writes as `[]` where a caller may leave them out, and where
 * the two mean the same: no condition, nobody, no role, no field required.
 */
const SAME_WHEN_EMPTY_LIST = new Set(['requires', 'auditors', 'managers', 'tees', 'required_roles', 'required_oids']);
/** Fields a vault writes as `null` where a caller may leave them out. */
const SAME_WHEN_NULL = new Set(['pinned_spki_sha256_hex', 'acceptable_tcb_statuses']);

/**
 * The value as what it says: the fields above are dropped when they say
 * nothing, at every depth, and an object's fields are put in one order.
 * Nothing else is touched, and lists keep their order, which carries meaning
 * (a rule names a manager by its place).
 */
export function normalise(v: unknown): unknown {
    if (Array.isArray(v)) return v.map(normalise);
    if (!isObject(v)) return v;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) {
        const raw = v[k];
        if (raw === undefined) continue;
        if (raw === null && SAME_WHEN_NULL.has(k)) continue;
        if (Array.isArray(raw) && raw.length === 0 && SAME_WHEN_EMPTY_LIST.has(k)) continue;
        out[k] = normalise(raw);
    }
    return out;
}

const digest = (v: unknown) => hex(sha256(new TextEncoder().encode(JSON.stringify(normalise(v) ?? null))));

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

/** The certificate field that carries the digest of the code a build runs. */
const WORKLOAD_OID = '1.3.6.1.4.1.65230.4.2';

/**
 * A build that can use the key: the code it runs (its workload digest, the
 * value a release is published under) and the machine image it runs on (its
 * measurements).
 *
 * `id` is what the build IS, in full, and is all that is ever compared. The
 * label shows the first characters of each and is for the eye only: eight
 * characters of a digest are cheap to match on purpose, so two builds are
 * never taken for one because their labels agree. `details` is the digest of
 * everything the entry says, so an entry that keeps its code and measurements
 * but changes anything else (which patch levels it accepts, where it is
 * attested) is not passed off as unchanged.
 */
function build(tee: unknown): { id: string; label: string; details: string } {
    const profile = isObject(tee) && isObject(tee.Tee) ? tee.Tee : tee;
    const p = isObject(profile) ? profile : {};
    const oids = Array.isArray(p.required_oids) ? p.required_oids : [];
    const workload = oids.find((o) => isObject(o) && o.oid === WORKLOAD_OID);
    const workloadValue = isObject(workload) && typeof workload.value === 'string' ? workload.value : '';
    const code = workloadValue.slice(0, 8);
    const measured = digest(p.measurements);
    const machine = measured.slice(0, 8);
    const name = typeof p.name === 'string' && p.name !== '' ? p.name : '';
    const label = code !== '' ? `${code} · ${machine}` : name !== '' ? `${name} ${machine}` : machine;
    return { id: digest([workloadValue, measured]), label, details: digest(profile) };
}

/** Whether a rule's principal list names a person (the owner or a manager). */
function namesPerson(principals: unknown): boolean {
    if (!Array.isArray(principals)) return false;
    return principals.some((p) => p === 'Owner' || (isObject(p) && ('Manager' in p || 'Owner' in p)));
}

/** Whether a rule asks for an approval before it lets a person act. */
function asksApproval(requires: unknown): boolean {
    if (!Array.isArray(requires)) return false;
    return requires.some((c) => isObject(c) && 'OidcStepUp' in c);
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

    const builds = tees.map(build);
    const buildDetails: Record<string, string> = {};
    for (const b of builds) buildDetails[b.id] = b.details;

    return {
        owner: person(principals.owner),
        approvers: managers.map((m) => person(m) ?? digest(m).slice(0, 8)),
        builds: builds.map((b) => b.label),
        buildIds: builds.map((b) => b.id),
        buildDetails,
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
    // By identity, never by label: two builds whose labels agree are still two.
    const added = b.builds.filter((_, i) => !a.buildIds.includes(b.buildIds[i]));
    const removed = a.builds.filter((_, i) => !b.buildIds.includes(a.buildIds[i]));
    if (added.length > 0 || removed.length > 0) changes.push({ kind: 'builds', added, removed });
    // A build that stays but whose entry says something else now (the patch
    // levels it accepts, where it is attested): a change the facts do not show.
    const buildChanged = a.buildIds.some((id) => b.buildIds.includes(id) && a.buildDetails[id] !== b.buildDetails[id]);
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
    return { changes, other: conditionsOnly || buildChanged || a.uncovered !== b.uncovered };
}
