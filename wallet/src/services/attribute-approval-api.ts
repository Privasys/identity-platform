// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Attribute step-up approvals — the wallet arm of "attribute step-up by push".
 *
 * A relying party the holder already signed into asked for MORE attributes
 * than the standing grant covers. The IdP's /authorize computed the delta and
 * pushed this device. Same trust model as vault approvals:
 *
 *  - The push carries only a capability (`approval`, 256-bit, short-TTL,
 *    single-completion). No request material transits push infrastructure.
 *  - The wallet fetches the request via GET /pending?challenge=<approval>
 *    (possession of the capability authorises viewing; no bearer).
 *  - The fetched WebAuthn options carry a challenge that IS the hash binding
 *    the approval to the authorize session, the client, and the EXACT
 *    requested key set — signing it approves that request and nothing else.
 *  - POST /complete is authenticated by the assertion itself, and carries the
 *    attribute VALUES for the full requested set (the IdP stores none between
 *    sessions), while the consent screen showed only the delta.
 */

import { signVaultAssertion } from './fido2';
import { useAuthStore, type Credential } from '../stores/auth';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
const IDP_ORIGIN = new URL(IDP_BASE).hostname;

export interface StepUpAssertionOptions {
    publicKey: {
        challenge: string;
        rpId?: string;
        allowCredentials?: Array<{ type: string; id: string }>;
    };
}

export interface AttributeApprovalRequest {
    /** The capability from the push — also the /complete challenge param. */
    approval: string;
    options: StepUpAssertionOptions;
    session_id: string;
    client_id: string;
    /** The DELTA: attribute keys this request added over the standing grant.
     *  This — and only this — is what the consent screen shows. */
    added: string[];
    /** The authorize descriptor (QR-payload shape: requestedAttributes,
     *  attributeRequirements, disclosureVouchers, clientId, sessionId…), so
     *  the consent + disclosure path is identical to a scanned sign-in. */
    payload: Record<string, unknown>;
    expires_at: number;
}

/**
 * Fetch one pending step-up by its capability. Returns null when it no longer
 * exists (completed already, or expired with its authorize session).
 */
export async function fetchAttributeApproval(
    approval: string,
): Promise<AttributeApprovalRequest | null> {
    const res = await fetch(
        `${IDP_BASE}/fido2/attribute-approval/pending?challenge=${encodeURIComponent(approval)}`,
    );
    if (res.status === 404) return null;
    if (!res.ok) {
        throw new Error(`fetch attribute approval failed (${res.status}): ${await res.text()}`);
    }
    const data = (await res.json()) as { pending?: AttributeApprovalRequest[] };
    return data.pending?.[0] ?? null;
}

/**
 * Resolve which of this device's pairwise credentials the request targets, by
 * matching allowCredentials against the on-device credential store. Returns
 * undefined when this device does not hold the holder credential.
 */
export function resolveStepUpCredential(
    options: StepUpAssertionOptions,
): Credential | undefined {
    const allowed = options.publicKey.allowCredentials ?? [];
    const { getCredentialById } = useAuthStore.getState();
    for (const c of allowed) {
        const local = getCredentialById(c.id);
        if (local) return local;
    }
    return undefined;
}

/**
 * Approve: sign the request-bound challenge with the resolved pairwise
 * credential and post the assertion plus the resolved attribute values.
 * The IdP verifies the assertion, re-checks the set binding against the
 * authorize session, and completes it — the browser's poll does the rest.
 */
export async function completeAttributeApproval(
    approval: string,
    options: StepUpAssertionOptions,
    credential: Credential,
    attributes: Record<string, string>,
): Promise<void> {
    const assertion = await signVaultAssertion(
        IDP_ORIGIN,
        credential.keyAlias,
        credential.credentialId,
        { ...options.publicKey, rpId: options.publicKey.rpId || credential.serverRpId },
    );
    const res = await fetch(
        `${IDP_BASE}/fido2/attribute-approval/complete?challenge=${encodeURIComponent(approval)}`,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ assertion, attributes }),
        },
    );
    if (!res.ok) {
        throw new Error(`approve failed (${res.status}): ${await res.text()}`);
    }
}

/**
 * Merge a step-up decision into the standing grant. A step-up consent covers
 * only the DELTA, but the stored standing consent is the whole grant — writing
 * the delta alone would silently revoke everything approved before.
 */
export function mergeStepUpConsent(
    prior: readonly string[] | undefined,
    approvedDelta: readonly string[],
): string[] {
    return Array.from(new Set([...(prior ?? []), ...approvedDelta]));
}
