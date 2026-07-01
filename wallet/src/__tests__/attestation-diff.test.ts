// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { diffTrustedAttestation } from '../services/attestation-diff';
import type { TrustedApp } from '../stores/trusted-apps';
import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);
const C = 'c'.repeat(64);
const D = 'd'.repeat(64);

function trustedTdx(overrides: Partial<TrustedApp> = {}): TrustedApp {
    return {
        rpId: 'app.apps-test.privasys.org',
        origin: 'app.apps-test.privasys.org',
        mrtd: A,
        codeHash: B,
        configRoot: C,
        teeType: 'tdx',
        lastVerified: 1750000000,
        credentialId: 'cred-1',
        ...overrides,
    };
}

function attTdx(overrides: Partial<AttestationResult> = {}): AttestationResult {
    return {
        valid: true,
        tee_type: 'tdx',
        mrtd: A,
        workload_code_hash: B,
        workload_config_merkle_root: C,
        ...overrides,
    } as AttestationResult;
}

describe('diffTrustedAttestation', () => {
    it('returns null when nothing changed', () => {
        expect(diffTrustedAttestation(trustedTdx(), attTdx())).toBeNull();
    });

    it('classifies a code-only change as app-update', () => {
        const diff = diffTrustedAttestation(trustedTdx(), attTdx({ workload_code_hash: D }));
        expect(diff?.kind).toBe('app-update');
        expect(diff?.changes).toEqual([
            { field: 'code', label: 'Application code', previous: B, current: D },
        ]);
        expect(diff?.summary).toMatch(/updated by its developer/);
    });

    it('classifies a config-only change as app-update', () => {
        const diff = diffTrustedAttestation(trustedTdx(), attTdx({ workload_config_merkle_root: D }));
        expect(diff?.kind).toBe('app-update');
        expect(diff?.changes.map((c) => c.field)).toEqual(['config']);
    });

    it('classifies an MRTD-only change as platform-update', () => {
        const diff = diffTrustedAttestation(trustedTdx(), attTdx({ mrtd: D }));
        expect(diff?.kind).toBe('platform-update');
        expect(diff?.changes).toEqual([
            { field: 'platform', label: 'Platform (MRTD)', previous: A, current: D },
        ]);
        expect(diff?.summary).toMatch(/platform hosting this application was upgraded/);
    });

    it('classifies platform + code changes as app-and-platform-update', () => {
        const diff = diffTrustedAttestation(
            trustedTdx(),
            attTdx({ mrtd: D, workload_code_hash: A })
        );
        expect(diff?.kind).toBe('app-and-platform-update');
        expect(diff?.changes.map((c) => c.field).sort()).toEqual(['code', 'platform']);
    });

    it('compares MRENCLAVE for SGX rows', () => {
        const trusted = trustedTdx({ teeType: 'sgx', mrenclave: A, mrtd: undefined });
        const att = attTdx({ mrenclave: D, mrtd: undefined });
        const diff = diffTrustedAttestation(trusted, att);
        expect(diff?.kind).toBe('platform-update');
        expect(diff?.changes[0].label).toBe('Platform (MRENCLAVE)');
    });

    it('surfaces a TEE-family migration as both platform axes', () => {
        const trusted = trustedTdx({ teeType: 'sgx', mrenclave: A, mrtd: undefined });
        const att = attTdx({ mrenclave: undefined, mrtd: D });
        const diff = diffTrustedAttestation(trusted, att);
        expect(diff?.kind).toBe('platform-update');
        expect(diff?.changes.map((c) => c.label).sort()).toEqual([
            'Platform (MRENCLAVE)',
            'Platform (MRTD)',
        ]);
    });

    it('treats a previously unrecorded field that is now present as a change', () => {
        const trusted = trustedTdx({ codeHash: undefined });
        const diff = diffTrustedAttestation(trusted, attTdx());
        expect(diff?.kind).toBe('app-update');
        expect(diff?.changes).toEqual([
            { field: 'code', label: 'Application code', previous: undefined, current: B },
        ]);
    });
});
