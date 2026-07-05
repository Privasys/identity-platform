// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Vault approvals — the wallet arm of the vault promote step-up.
 *
 * The CLI (owner bearer) drives POST /fido2/vault-approval/begin, which records
 * a pending approval and pushes the wallet. The wallet lists the pending
 * approvals here, signs the operation-bound challenge with its existing fido2
 * credential, and POSTs the assertion to /complete — which issues the
 * operation-bound token the CLI collects. No browser, no system passkey.
 *
 * These endpoints are served by privasys.id over normal HTTPS (same as the
 * browser ceremony page), so we use plain fetch (mirroring recovery-api.ts),
 * not the RA-TLS transport fido2.ts uses for the enclave.
 */

import { signVaultAssertion } from './fido2';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
// The IdP host used for the WebAuthn clientDataJSON origin + rpIdHash. Must match
// the IdP RPID/RPOrigins (privasys.id).
const IDP_ORIGIN = new URL(IDP_BASE).hostname;

export interface VaultApprovalSummary {
    operation: string; // "promote" | "export"
    handle: string;
    measurement: string; // the profile_binding_digest (hex), empty for export
}

export interface VaultApprovalRequest {
    vault_op: string;
    options: { publicKey: { challenge: string; rpId?: string; allowCredentials?: Array<{ type: string; id: string }> } };
    summary: VaultApprovalSummary;
    expires_at: number;
}

function walletAuth(walletSessionToken: string): HeadersInit {
    return { Authorization: `Bearer wallet:${walletSessionToken}` };
}

/** List the owner's live pending vault approvals. */
export async function listVaultApprovals(walletSessionToken: string): Promise<VaultApprovalRequest[]> {
    const res = await fetch(`${IDP_BASE}/fido2/vault-approval/pending`, {
        headers: walletAuth(walletSessionToken),
    });
    if (!res.ok) {
        throw new Error(`list vault approvals failed (${res.status}): ${await res.text()}`);
    }
    const data = (await res.json()) as { pending?: VaultApprovalRequest[] };
    return data.pending || [];
}

/**
 * Approve one pending request: sign the operation-bound challenge with the
 * account's fido2 credential (biometric-gated in NativeKeys.sign) and post the
 * assertion to /complete. The IdP issues + stashes the operation-bound token the
 * CLI is polling for.
 */
export async function approveVaultApproval(
    req: VaultApprovalRequest,
    keyAlias: string,
    credentialId: string,
): Promise<void> {
    const assertion = await signVaultAssertion(IDP_ORIGIN, keyAlias, credentialId, req.options.publicKey);
    const res = await fetch(
        `${IDP_BASE}/fido2/vault-approval/complete?challenge=${encodeURIComponent(req.vault_op)}`,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(assertion),
        },
    );
    if (!res.ok) {
        throw new Error(`approve failed (${res.status}): ${await res.text()}`);
    }
}

/**
 * Register the wallet's Expo push token with the IdP so it can push
 * vault-approval (and other) notifications keyed by the owner sub. The wallet
 * otherwise only relays its token through the broker, so without this the IdP
 * has no target token for the owner.
 */
export async function registerPushTokenWithIdp(walletSessionToken: string, expoPushToken: string): Promise<void> {
    const res = await fetch(`${IDP_BASE}/push-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...walletAuth(walletSessionToken) },
        body: JSON.stringify({ push_token: expoPushToken }),
    });
    if (!res.ok) {
        throw new Error(`register push token failed (${res.status})`);
    }
}
