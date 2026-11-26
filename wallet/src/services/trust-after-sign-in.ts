// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What the trusted-app record becomes after a sign-in with a passkey the
 * wallet already held.
 *
 * The time is always refreshed. The measurements are replaced only by ones
 * the attestation service verified in this same flow, for this same host:
 * either they matched the record, or the holder approved the change. A flow
 * the holder continued although verification was unreachable or invalid
 * records nothing new, so a failed verification never becomes silent trust on
 * the next sign-in. A leaf module, so the rule is tested without the React
 * Native runtime.
 */

/** The measurement fields of a trusted-app record. */
export interface TrustMeasurements {
    mrenclave?: string;
    mrtd?: string;
    rtmr1?: string;
    rtmr2?: string;
    codeHash?: string;
    configRoot?: string;
}

/** The slice of an attestation result this rule reads. */
export interface AttestedMeasurements {
    mrenclave?: string;
    mrtd?: string;
    rtmr1?: string;
    rtmr2?: string;
    workload_code_hash?: string;
    workload_config_merkle_root?: string;
    tee_type?: string;
}

export function trustAfterSignIn<T extends TrustMeasurements & { appName?: string; teeType: string; lastVerified: number }>(
    existing: T,
    flow: {
        /** What this flow attested, if anything. */
        attested: AttestedMeasurements | null;
        /** True only when the attestation service verified it in this flow. */
        verified: boolean;
        /** True when the host attested in this flow is this record's. */
        sameHost: boolean;
        appName?: string;
        nowSeconds: number;
    },
): T {
    const att = flow.verified && flow.sameHost ? flow.attested : null;
    return {
        ...existing,
        ...(att
            ? {
                  mrenclave: att.mrenclave,
                  mrtd: att.mrtd,
                  rtmr1: att.rtmr1,
                  rtmr2: att.rtmr2,
                  codeHash: att.workload_code_hash,
                  configRoot: att.workload_config_merkle_root,
                  teeType: att.tee_type || existing.teeType,
              }
            : {}),
        appName: flow.appName ?? existing.appName,
        lastVerified: flow.nowSeconds,
    };
}
