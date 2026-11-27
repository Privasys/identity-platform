// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Whether a detail is verified, derived from its verification records and
 * never stored beside them.
 *
 * A detail is verified when the wallet holds the Attribute Verifier's proof
 * for it (what privasys.id discloses to an app, and the only ground on which
 * it sets `email_verified`), or when the identity verifier certified it from
 * an identity document. A provider's bare claim is where the value came from,
 * not a verification. A leaf module, so the rule is tested without the React
 * Native runtime.
 */

/** The slice of a verification record this rule reads. */
export interface ProofSlice {
    proof?: string;
    assurance?: 'none' | 'provider' | 'gov';
}

/** A record that holds a proof the wallet can disclose to an app. */
export function isDisclosableProof(v: ProofSlice): boolean {
    return !!v.proof && v.assurance === 'provider';
}

/** Whether this detail is verified. */
export function isVerified(attr: { verifications?: ProofSlice[] }): boolean {
    return (attr.verifications ?? []).some((v) => isDisclosableProof(v) || v.assurance === 'gov');
}
