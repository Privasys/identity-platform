// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

export interface AttestationResult {
    valid: boolean;
    tee_type?: 'sgx' | 'tdx' | 'sev-snp' | 'nvidia-gpu';
    mrenclave?: string;
    mrsigner?: string;
    mrtd?: string;

    // Platform / VM-wide OIDs (.65230.1.x, .65230.2.x).
    config_merkle_root?: string;
    combined_workloads_hash?: string;
    dek_origin?: string;
    attestation_servers_hash?: string;

    // Per-workload OIDs (.65230.3.x).
    workload_config_merkle_root?: string;
    workload_code_hash?: string;
    workload_image_ref?: string;
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

/**
 * Failure category returned by the native RA-TLS layer, so callers can pick the
 * right recovery UX:
 *  - `as_unreachable` — attestation service down/timeout/uninterpretable; no
 *    clear verdict → offer the user "continue anyway".
 *  - `quote_invalid` — the quote itself failed a local check (measurement,
 *    report_data/binder, TEE, image profile) → a definite bad verdict.
 *  - `as_rejected` — the attestation service returned a clear negative verdict.
 *  - `connection` — could not reach/handshake the enclave → hard error, retry.
 *  - `config` — bad policy/arguments → programming error.
 */
export type VerifyErrorKind =
    | 'config'
    | 'connection'
    | 'quote_invalid'
    | 'as_unreachable'
    | 'as_rejected';

export interface AttestationError {
    error: string;
    /** Present on `verify` failures and on data-plane binding failures. */
    kind?: VerifyErrorKind;
}

export interface PostResult {
    status: number;
    body: string;
}
