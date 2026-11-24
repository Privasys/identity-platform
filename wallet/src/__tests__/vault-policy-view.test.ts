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
