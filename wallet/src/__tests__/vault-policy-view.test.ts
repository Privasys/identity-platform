// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { policyDiff, policyFacts } from '@/services/vault-policy-view';

const stepUp = { OidcStepUp: { required_amr: ['webauthn'], operation_bound: true, fresh_for_seconds: 300, binding: 2 } };

/** An app storage key's rules, as the control plane writes them on a v2 constellation. */
function rules(over: Record<string, unknown> = {}) {
    return {
        version: 1,
        principals: {
            owner: { Oidc: { issuer: 'https://privasys.id', sub: 'r2C7Km0L2j0TbNuIPWd2JaxsayWawjP7jvRtMlBzVPw', required_roles: [] } },
            managers: [{ Oidc: { issuer: 'https://privasys.id', sub: '', required_roles: ['privasys-platform-test:app:31b9:approver'] } }],
            auditors: [],
            tees: [{ Tee: { name: 'v0.1.1', measurements: [{ Mrtd: 'aa' }] } }, { Tee: { name: 'v0.1.2', measurements: [{ Mrtd: 'bb' }] } }],
        },
        operations: [
            { ops: ['ExportKey'], principals: ['AnyTee'], requires: [] },
            { ops: ['PromoteProfile'], principals: ['Owner', { Manager: 0 }], requires: [stepUp] },
            { ops: ['UpdatePolicy', 'DeleteKey'], principals: ['Owner', { Manager: 0 }], requires: [stepUp] },
            { ops: ['ExportKey'], principals: ['Owner'], requires: [stepUp] },
        ],
        lifecycle: { ttl_seconds: 7776000, auto_migrate_to_next_attestation_profile: false },
        ...over,
    };
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));

describe('what a key\'s rules say', () => {
    it('names the owner, the approvers, the builds and what needs approval', () => {
        const f = policyFacts(rules());
        expect(f.owner).toBe('r2C7Km0L… · privasys.id');
        expect(f.approvers).toEqual(['approver · privasys.id']);
        expect(f.builds).toHaveLength(2);
        expect(f.builds[0]).toMatch(/^v0\.1\.1 [0-9a-f]{8}$/);
        expect(f.gates).toEqual({ PromoteProfile: 'approval', UpdatePolicy: 'approval', DeleteKey: 'approval', ExportKey: 'approval' });
        expect(f.followsUpdates).toBe(false);
    });

    it('says an act is open when one rule lets a person do it with no approval', () => {
        const open = rules();
        (open.operations as any[]).push({ ops: ['DeleteKey'], principals: ['Owner'], requires: [] });
        expect(policyFacts(open).gates.DeleteKey).toBe('open');
        // An app's own export is not a person's: it does not make export open.
        expect(policyFacts(rules()).gates.ExportKey).toBe('approval');
    });

    it('says an act is allowed to no person when no rule names one', () => {
        const none = rules({ operations: [{ ops: ['ExportKey'], principals: ['AnyTee'], requires: [] }] });
        expect(policyFacts(none).gates).toEqual({ PromoteProfile: 'none', UpdatePolicy: 'none', DeleteKey: 'none', ExportKey: 'none' });
    });

    it('reads fewer facts from a shape it does not know, never a wrong one', () => {
        const f = policyFacts({ something: 'else' });
        expect(f.owner).toBeUndefined();
        expect(f.approvers).toEqual([]);
        expect(f.builds).toEqual([]);
    });
});

describe('what changes between two sets of rules', () => {
    it('is only the builds when a measurement is retired', () => {
        const next = clone(rules());
        (next.principals.tees as unknown[]).shift();
        const d = policyDiff(rules(), next);
        expect(d.other).toBe(false);
        expect(d.changes).toEqual([{ kind: 'builds', added: [], removed: [expect.stringMatching(/^v0\.1\.1 /)] }]);
    });

    it('is only following updates when that is switched on', () => {
        const next = rules({ lifecycle: { ttl_seconds: 7776000, auto_migrate_to_next_attestation_profile: true } });
        expect(policyDiff(rules(), next)).toEqual({ changes: [{ kind: 'followsUpdates', before: false, after: true }], other: false });
    });

    it('shows each act that gains an approval, and nothing else', () => {
        const open = clone(rules());
        for (const r of open.operations as any[]) if (r.principals.includes('Owner')) r.requires = [];
        const d = policyDiff(open, rules());
        expect(d.other).toBe(false);
        expect(d.changes.map((c) => (c.kind === 'gate' ? `${c.op}:${c.before}>${c.after}` : c.kind))).toEqual([
            'PromoteProfile:open>approval',
            'UpdatePolicy:open>approval',
            'DeleteKey:open>approval',
            'ExportKey:open>approval',
        ]);
    });

    it('flags a condition weakened behind a gate that reads the same', () => {
        const weaker = clone(rules());
        (weaker.operations as any[])[1].requires = [{ OidcStepUp: { ...stepUp.OidcStepUp, operation_bound: false } }];
        expect(policyDiff(rules(), weaker)).toEqual({ changes: [], other: true });
    });

    it('flags a change the facts do not cover', () => {
        expect(policyDiff(rules(), rules({ lifecycle: { ttl_seconds: 60, auto_migrate_to_next_attestation_profile: false } })).other).toBe(true);
        const tee = clone(rules());
        (tee.operations as any[])[0].ops = ['ExportKey', 'Sign'];
        expect(policyDiff(rules(), tee).other).toBe(true);
    });

    it('shows a new owner or approver', () => {
        const next = clone(rules());
        (next.principals.owner as any).Oidc.sub = 'someone-else-entirely-0000000000';
        (next.principals.managers as unknown[]).length = 0;
        const kinds = policyDiff(rules(), next).changes.map((c) => c.kind);
        expect(kinds).toEqual(['owner', 'approvers']);
    });
});

describe('the same rules written two ways', () => {
    // A real key's rules as its vaults return them (every default written
    // out) and as the control plane writes its proposal (defaults left out),
    // for a retire of one of two builds.
    const { stored, typed } = require('./fixtures/policy-forms.json');
    const { normalise } = require('@/services/vault-policy-view');

    it('show only what really changes: one build removed, nothing added', () => {
        const d = policyDiff(stored, typed);
        expect(d.changes).toEqual([{ kind: 'builds', added: [], removed: [expect.stringMatching(/^90227e2e · [0-9a-f]{8}$/)] }]);
        expect(d.other).toBe(false);
    });

    it('show nothing when the two say the same', () => {
        const same = clone(stored);
        // The typed form of the very same rules: defaults dropped.
        const dropped = normalise(same);
        expect(JSON.stringify(dropped)).not.toEqual(JSON.stringify(same));
        expect(policyDiff(same, dropped)).toEqual({ changes: [], other: false });
        expect(policyDiff(dropped, same)).toEqual({ changes: [], other: false });
    });

    it('name a build by the code it runs and the machine image under it', () => {
        expect(policyFacts(typed).builds).toEqual([expect.stringMatching(/^237a912e · [0-9a-f]{8}$/)]);
        // The build that stays carries one label in both forms.
        expect(policyFacts(stored).builds).toContain(policyFacts(typed).builds[0]);
    });

    it('do not pass off a build whose entry says something else as unchanged', () => {
        const next = clone(stored);
        next.principals.tees[0].Tee.acceptable_tcb_statuses = [];
        const d = policyDiff(stored, next);
        expect(d.changes).toEqual([]);
        expect(d.other).toBe(true);
    });

    it('never read a strict patch-level check and no check at all as one', () => {
        // null or absent: no check. An empty list: the strictest there is.
        const none = clone(stored);
        none.principals.tees[0].Tee.acceptable_tcb_statuses = null;
        const absent = clone(stored);
        delete absent.principals.tees[0].Tee.acceptable_tcb_statuses;
        const strict = clone(stored);
        strict.principals.tees[0].Tee.acceptable_tcb_statuses = [];
        expect(policyDiff(none, strict).other).toBe(true);
        expect(policyDiff(strict, none).other).toBe(true);
        expect(policyDiff(strict, absent).other).toBe(true);
        // null and absent are the same thing said two ways.
        expect(policyDiff(none, absent)).toEqual({ changes: [], other: false });
    });

    it('keep an empty value that is not on the list as it was sent', () => {
        const a = clone(stored);
        a.lifecycle.extra = [];
        expect(policyDiff(stored, a).other).toBe(true);
        expect(normalise({ requires: [], other: [], n: null, pinned_spki_sha256_hex: null })).toEqual({ other: [], n: null });
    });

    it('take two builds for two when only their labels agree', () => {
        // Same first eight characters of the code digest, same machine image.
        const next = clone(stored);
        const oid = next.principals.tees[0].Tee.required_oids[0];
        oid.value = oid.value.slice(0, 8) + 'f'.repeat(oid.value.length - 8);
        expect(policyFacts(next).builds[0]).toBe(policyFacts(stored).builds[0]);
        const d = policyDiff(stored, next);
        expect(d.changes).toEqual([{ kind: 'builds', added: [policyFacts(next).builds[0]], removed: [policyFacts(stored).builds[0]] }]);
    });

    it('still see a default that is given a value', () => {
        const next = clone(stored);
        next.principals.tees[0].Tee.attestation_servers[0].pinned_spki_sha256_hex = 'ab'.repeat(32);
        expect(policyDiff(stored, next).other).toBe(true);
        const withAuditor = clone(stored);
        withAuditor.principals.auditors = [{ Oidc: { issuer: 'https://privasys.id', sub: 'someone' } }];
        expect(policyDiff(stored, withAuditor).other).toBe(true);
    });
});
