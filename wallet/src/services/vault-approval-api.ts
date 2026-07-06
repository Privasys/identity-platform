// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Vault approvals — the wallet arm of the vault promote/export step-up.
 *
 * Identity model (matches the platform's pairwise design): the vault key is
 * owned by the user's PAIRWISE identity for the platform RP. The server holds
 * no mapping between pairwise identities and the canonical one — that mapping
 * lives only on this device, in the auth store's per-RP credentials. So:
 *
 *  - The push carries only a capability (`vault_op`, 256-bit, short-TTL,
 *    single-use). No identity or operation material transits push infra.
 *  - The wallet fetches the request via GET /pending?challenge=<vault_op>
 *    (possession of the capability authorises viewing; no bearer).
 *  - The fetched WebAuthn options name the owner's credential in
 *    `allowCredentials`; the wallet resolves WHICH of its on-device pairwise
 *    credentials that is by credential id, and signs with that key.
 *  - POST /complete is authenticated by the assertion itself.
 */

import { signVaultAssertion } from './fido2';
import { useAuthStore, type Credential } from '../stores/auth';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
const IDP_ORIGIN = new URL(IDP_BASE).hostname;

export interface VaultApprovalSummary {
    operation: string; // "promote" | "export"
    handle: string;
    measurement: string; // profile_binding_digest (hex); empty for export
}

export interface VaultApprovalRequest {
    vault_op: string;
    options: {
        publicKey: {
            challenge: string;
            rpId?: string;
            allowCredentials?: Array<{ type: string; id: string }>;
        };
    };
    summary: VaultApprovalSummary;
    expires_at: number;
}

/**
 * Fetch one pending approval by its capability. Returns null when it does not
 * exist (approved already, or expired).
 */
export async function fetchVaultApproval(vaultOp: string): Promise<VaultApprovalRequest | null> {
    const res = await fetch(
        `${IDP_BASE}/fido2/vault-approval/pending?challenge=${encodeURIComponent(vaultOp)}`,
    );
    if (res.status === 404) return null;
    if (!res.ok) {
        throw new Error(`fetch vault approval failed (${res.status}): ${await res.text()}`);
    }
    const data = (await res.json()) as { pending?: VaultApprovalRequest[] };
    return data.pending?.[0] ?? null;
}

/**
 * Resolve which of this device's pairwise credentials the request targets, by
 * matching the request's allowCredentials against the on-device credential
 * store. Returns undefined when this device does not hold the owner credential.
 */
export function resolveApprovalCredential(req: VaultApprovalRequest): Credential | undefined {
    const allowed = req.options.publicKey.allowCredentials ?? [];
    const { getCredentialById } = useAuthStore.getState();
    for (const c of allowed) {
        const local = getCredentialById(c.id);
        if (local) return local;
    }
    return undefined;
}

/**
 * Approve: sign the operation-bound challenge with the resolved pairwise
 * credential (biometric-gated natively in NativeKeys.sign) and post the
 * assertion to /complete. The IdP verifies it against the owner's registered
 * credential and stashes the operation-bound token for the CLI's poll.
 */
export async function approveVaultApproval(req: VaultApprovalRequest, credential: Credential): Promise<void> {
    const assertion = await signVaultAssertion(
        IDP_ORIGIN,
        credential.keyAlias,
        credential.credentialId,
        { ...req.options.publicKey, rpId: req.options.publicKey.rpId || credential.serverRpId },
    );
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
 * Register the wallet's Expo push token with the IdP under a given wallet
 * session's identity. Called after each successful RP sign-in with THAT RP's
 * session, so every pairwise identity that owns vault keys can be pushed —
 * without the IdP learning any pairwise linkage it doesn't already have.
 */
export async function registerPushTokenWithIdp(walletSessionToken: string, expoPushToken: string): Promise<void> {
    const res = await fetch(`${IDP_BASE}/push-token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer wallet:${walletSessionToken}`,
        },
        body: JSON.stringify({ push_token: expoPushToken }),
    });
    if (!res.ok) {
        throw new Error(`register push token failed (${res.status})`);
    }
}

// The set of capabilities seen this session — and the fetch/prune that turns
// them into the live `pending` list — now lives in stores/vaultApprovals, so
// the Home banner and the approvals screen share one reactive source. This
// module stays the thin transport layer (fetch/approve/resolve/push-token).
