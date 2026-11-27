// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Whether the wallet tells the holder a detail is verified.
 *
 * An email address counts as verified for an app only when the wallet holds
 * the Attribute Verifier's proof for it: privasys.id sets `email_verified`
 * from a disclosure of that proof, never from a provider's bare claim. So the
 * wallet says "verified" for an address on the same ground, and offers to
 * verify it again otherwise. A leaf module, so the rule is tested without the
 * React Native runtime.
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

/** Whether to show this attribute as verified. */
export function shownVerified(attr: { key: string; verified: boolean; verifications?: ProofSlice[] }): boolean {
    if (attr.key === 'email') return (attr.verifications ?? []).some(isDisclosableProof);
    return attr.verified;
}
