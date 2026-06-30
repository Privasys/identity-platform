// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Canonical attestation-OID digests used in EncAuth vouchers.
 *
 * Pure (no native/React-Native deps) so it is unit-testable on its own and
 * shared by the wallet's voucher builder. Kept byte-for-byte in lockstep with
 * the Go manager (enclave-os-virtual/internal/sessionrelay/workload_digest.go)
 * — see the KAT in src/__tests__/workload-digest.test.ts.
 */
import { sha256 } from '@noble/hashes/sha2.js';

import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';

/**
 * Deterministic serialisation of an OID-value subset: drop empty/undefined
 * values, sort the remaining keys ascending, render each as `key=value`, join
 * by '\n', then SHA-256 the UTF-8 bytes. Stability across versions matters;
 * renaming a key silently changes the digest.
 */
export function hashOidSubset(fields: Record<string, string | undefined>): Uint8Array {
    const lines = Object.keys(fields)
        .filter((k) => fields[k] !== undefined && fields[k] !== '')
        .sort()
        .map((k) => `${k}=${fields[k]}`);
    return sha256(new TextEncoder().encode(lines.join('\n')));
}

/** SHA-256 over the platform half (TEE + 1.x/2.x OIDs) of a verified attestation. */
export function encMeasHash(att: AttestationResult): Uint8Array {
    return hashOidSubset({
        tee_type: att.tee_type,
        mrenclave: att.mrenclave,
        mrsigner: att.mrsigner,
        mrtd: att.mrtd,
        config_merkle_root: att.config_merkle_root,
        combined_workloads_hash: att.combined_workloads_hash,
        dek_origin: att.dek_origin,
        attestation_servers_hash: att.attestation_servers_hash,
    });
}

/**
 * SHA-256 over the workload-measurement OIDs (3.1 config-merkle, 3.2 code
 * hash, 3.3 image-ref, 3.4 key-source) of a verified attestation — CBOR
 * field 4 of the voucher. Named `app_id` in the wire format, but it is NOT
 * the static OID 3.6 app-id; it moves with the OID 3.2 code hash. The enclave
 * re-verifies it at consumption when the host arms the per-app binding
 * (SetExpectedWorkloadDigest, Sc 1 — see enc-pub-plan.md), so it must match
 * the manager's WorkloadDigest byte-for-byte. (Renamed from `appIdHash`,
 * ≤2026-06-29.)
 */
export function workloadDigestHash(att: AttestationResult): Uint8Array {
    return hashOidSubset({
        workload_config_merkle_root: att.workload_config_merkle_root,
        workload_code_hash: att.workload_code_hash,
        workload_image_ref: att.workload_image_ref,
        workload_key_source: att.workload_key_source,
    });
}
