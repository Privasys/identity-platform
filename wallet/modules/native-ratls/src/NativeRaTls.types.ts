// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

export interface AttestationResult {
    valid: boolean;
    tee_type?: 'sgx' | 'tdx' | 'sev-snp' | 'nvidia-gpu';
    mrenclave?: string;
    mrsigner?: string;
    mrtd?: string;
    config_merkle_root?: string;
    code_hash?: string;
    /** Per-workload OCI image reference, on enclave-os-virtual container certs. */
    image_ref?: string;
    attestation_servers_hash?: string;
    dek_origin?: string;
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
