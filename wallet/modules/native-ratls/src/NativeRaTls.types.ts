// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

export interface AttestationResult {
    valid: boolean;
    tee_type?: 'sgx' | 'tdx' | 'sev-snp' | 'nvidia-gpu';
    mrenclave?: string;
    mrsigner?: string;
    mrtd?: string;

    // Platform / VM-wide OIDs. Present on enclave-os-mini SGX certs and
    // on enclave-os-virtual management certs. Cover the entire VM.
    /** `OID_CONFIG_MERKLE_ROOT` (.65230.1.1). */
    config_merkle_root?: string;
    /** `OID_COMBINED_WORKLOADS_HASH` (.65230.2.5) — hash of all workloads. */
    combined_workloads_hash?: string;
    /** `OID_DEK_ORIGIN` (.65230.2.6) — platform DEK origin (UTF-8). */
    dek_origin?: string;
    /** `OID_ATTESTATION_SERVERS_HASH` (.65230.2.7). */
    attestation_servers_hash?: string;

    // Per-workload / container OIDs. Present only on enclave-os-virtual
    // container RA-TLS certs; each value is scoped to that container.
    /** `OID_WORKLOAD_CONFIG_MERKLE_ROOT` (.65230.3.1). */
    workload_config_merkle_root?: string;
    /** `OID_WORKLOAD_CODE_HASH` (.65230.3.2) — this container's code/image digest. */
    workload_code_hash?: string;
    /** `OID_WORKLOAD_IMAGE_REF` (.65230.3.3) — OCI image reference (UTF-8). */
    workload_image_ref?: string;
    /** `OID_WORKLOAD_KEY_SOURCE` (.65230.3.4) — per-workload DEK origin (UTF-8). */
    workload_key_source?: string;

    quote_verification_status?: string;
    advisory_ids?: string[];
    cert_subject: string;
    cert_not_before: string;
    cert_not_after: string;
    custom_oids?: Array<{ oid: string; label: string; value_hex: string }>;
}

export interface VerificationPolicy {
    tee: 'sgx' | 'tdx' | 'sev-snp' | 'nvidia-gpu';
    mrenclave?: string;
    mrsigner?: string;
    mrtd?: string;
    report_data_mode?: 'deterministic' | 'challenge' | 'skip';
    nonce?: string;
    attestation_server?: string;
    attestation_server_token?: string;
}

export interface AttestationError {
    error: string;
}

export interface PostResult {
    status: number;
    body: string;
}
