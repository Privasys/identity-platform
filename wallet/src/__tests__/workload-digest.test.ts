// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Workload-digest KAT — the wallet half.
 *
 * The same vector is pinned in the Go manager
 * (enclave-os-virtual/internal/sessionrelay/workload_digest_test.go) and both
 * MUST reproduce these digests byte-for-byte. This is the gate for arming the
 * Sc 1 per-app workload-digest wake (SetExpectedWorkloadDigest): the wallet
 * issues the voucher's field 4 via workloadDigestHash, and the manager
 * re-verifies it at consumption against its own WorkloadDigest — a mismatch
 * would either never wake or always wake. The expected hex was computed
 * independently (SHA-256 over the canonical string), so a match proves
 * TS ↔ Go agreement, not mutual agreement on a wrong value.
 *
 * Changing any pinned constant is a wire-format break — bump a version and add
 * a new vector instead.
 */
import { workloadDigestHash } from '../services/oid-digest';

import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';

const toHex = (b: Uint8Array): string =>
    Array.from(b)
        .map((x) => x.toString(16).padStart(2, '0'))
        .join('');

const CMR = '1111111111111111111111111111111111111111111111111111111111111111';
const CODE = '2222222222222222222222222222222222222222222222222222222222222222';
const REF = 'ghcr.io/privasys/container-app-example';
const KS = 'generated';

const VEC1 = '518939c94cf5980105541518a33140d99f7f19cffaeee131bdbe0bc3c9b851a3';
const VEC2 = '471017351a58db1e6e8ce4b70f8e68129b1444110d06229dc80998c39cef4f37';

describe('workloadDigestHash KAT (must match the Go manager)', () => {
    it('all four fields', () => {
        const d = workloadDigestHash({
            workload_config_merkle_root: CMR,
            workload_code_hash: CODE,
            workload_image_ref: REF,
            workload_key_source: KS,
        } as AttestationResult);
        expect(toHex(d)).toBe(VEC1);
    });

    it('empty key_source is dropped', () => {
        const d = workloadDigestHash({
            workload_config_merkle_root: CMR,
            workload_code_hash: CODE,
            workload_image_ref: REF,
            workload_key_source: '',
        } as AttestationResult);
        expect(toHex(d)).toBe(VEC2);
    });

    it('a code-hash (OID 3.2) change moves the digest (the wake)', () => {
        const d = workloadDigestHash({
            workload_config_merkle_root: CMR,
            workload_code_hash: '3333333333333333333333333333333333333333333333333333333333333333',
            workload_image_ref: REF,
            workload_key_source: KS,
        } as AttestationResult);
        expect(toHex(d)).not.toBe(VEC1);
    });
});
