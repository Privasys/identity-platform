// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';

/**
 * Resolve the per-endpoint code hash. Container RA-TLS certs in
 * enclave-os-virtual carry `workload_code_hash` (.65230.3.2 — scoped to
 * one container); platform/management certs and enclave-os-mini SGX certs
 * carry `combined_workloads_hash` (.65230.2.5 — covers the whole VM /
 * enclave). Prefer the workload-scoped value when present.
 */
export function effectiveCodeHash(att: AttestationResult): string | undefined {
    return att.workload_code_hash ?? att.combined_workloads_hash;
}

/**
 * Resolve the per-endpoint config Merkle root. Same workload-vs-platform
 * scoping as `effectiveCodeHash`.
 */
export function effectiveConfigMerkleRoot(att: AttestationResult): string | undefined {
    return att.workload_config_merkle_root ?? att.config_merkle_root;
}

/**
 * Resolve the DEK origin / per-workload key source. Container certs use
 * `workload_key_source`; platform certs use `dek_origin`.
 */
export function effectiveDekOrigin(att: AttestationResult): string | undefined {
    return att.workload_key_source ?? att.dek_origin;
}
