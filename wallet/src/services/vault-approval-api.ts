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

import { resolveApp } from './app-resolve';
import { myDeviceTag } from './devices';
import { signVaultAssertion } from './fido2';
import { fetchReleaseProvenance, publicApiGet, type ReleaseProvenance } from './release-provenance';
import {
    dashedAppId,
    isVaultBatchId,
    verifyVaultBatch,
    VaultBatchRefused,
    type VaultBatchRefusal,
    type VerifiedVaultBatch,
} from './vault-approval-batch';
import { useAuthStore, type Credential } from '../stores/auth';
import type { BindingFields } from './vault-approval-v2';
import type { VaultIdentity } from './vault-identity';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';
const IDP_ORIGIN = new URL(IDP_BASE).hostname;

export interface VaultApprovalSummary {
    operation: string; // "promote" | "export"
    handle: string;
    measurement: string; // profile_binding_digest (hex); empty for export
    policy_version?: number;
    // Advisory display context supplied by the initiator (the owner's CLI) to
    // make the operation human-recognisable. NOT part of the vault_op binding —
    // the enclave enforces only the operation tuple — so these are hints that
    // help the user decide, not a security guarantee. The measurement digest
    // remains the cryptographic truth.
    app_name?: string;
    version?: string; // e.g. "v1.2.3 · git:a1b2c3d · 23 Jun 2026"
    source?: string;
    key_type?: string; // export: the key kind (e.g. Aes256GcmKey)
    // What the operation does, in plain words (an app policy: the callers it
    // admits, from which machines, what it depends on). Advisory, like the
    // rest: the digest is what the approval binds.
    summary?: string;
    // Identifiers the wallet uses to fetch mgmt release provenance itself (the
    // published release + old→new code diff for the promote target).
    app_id?: string;
    version_id?: string;
    // Reshare (renewing a threshold key): the resharing context's inputs, which
    // the wallet recomputes the measurement from (services/vault-reshare).
    target_mrenclave?: string;
    target_vaults?: string;
    threshold?: string;
    helpers?: string;
    public_key?: string;
    // Binding v2 (services/vault-approval-v2): every field of the text the
    // approval binds, the identities of the vaults it names, and for a policy
    // update the policy it installs. The wallet checks them all before Approve.
    binding?: BindingFields;
    // A v1 approval may say what it binds (its nonce and expiry), so the
    // wallet recomputes the challenge from what the card shows.
    nonce?: string;
    exp?: number;
    member_identities?: VaultIdentity[];
    new_policy?: unknown;
    // A delete_after for a created successor: the key the old one waits for.
    successor_handle?: string;
    // The vaults' release tag (e.g. "vault-v0.41.0"), a hint for the wallet's
    // own lookup on GitHub. Bound by nothing and believed for nothing.
    vault_release?: string;
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
 * List every approval currently pending for the identity behind a wallet
 * session. This is how the wallet finds an approval when no push arrived — a
 * push is best-effort (it may have no registered token, or be dropped by the
 * transport with no receipt), and until this existed a lost push meant the
 * request was simply invisible until it expired.
 *
 * It leaks no new linkage: the caller proves a single session, and the IdP
 * already knows that session's subject — the same basis on which it accepts the
 * push-token registration. It resolves ONE identity per call, never a join
 * across the wallet's pairwise identities.
 */
export async function listVaultApprovals(
    walletSessionToken: string,
): Promise<VaultApprovalRequest[]> {
    const res = await fetch(`${IDP_BASE}/fido2/vault-approval/pending`, {
        headers: { Authorization: `Bearer wallet:${walletSessionToken}` },
    });
    if (res.status === 401 || res.status === 404) return [];
    if (!res.ok) {
        throw new Error(`list vault approvals failed (${res.status}): ${await res.text()}`);
    }
    const data = (await res.json()) as { pending?: VaultApprovalRequest[] };
    return data.pending ?? [];
}

/**
 * Resolve which of this device's pairwise credentials the request targets, by
 * matching the request's allowCredentials against the on-device credential
 * store. Returns undefined when this device does not hold the owner credential.
 */
export function resolveApprovalCredential(req: Pick<VaultApprovalRequest, 'options'>): Credential | undefined {
    const allowed = req.options.publicKey.allowCredentials ?? [];
    const { getCredentialById } = useAuthStore.getState();
    for (const c of allowed) {
        const local = getCredentialById(c.id);
        if (local) return local;
    }
    return undefined;
}

/**
 * Evidence for the "Wrong device or identity" alert: which credential id(s)
 * the request targets vs what this device actually holds. A bare "wrong
 * device" claim is undiagnosable after the fact (2026-07-30: a prod promote
 * was refused on the owner's only device and the alert carried nothing to
 * reason from) — with the two id lists side by side, one screenshot tells
 * whether the store is missing the credential, holds a rotated successor, or
 * was empty. Short prefixes only: credential ids are public identifiers, but
 * there is no reason to fill the screen.
 */
export function describeApprovalMismatch(req: Pick<VaultApprovalRequest, 'options'>): string {
    const short = (s: string) => (s && s.length > 12 ? `${s.slice(0, 10)}…` : s || '(empty)');
    const requested = (req.options.publicKey.allowCredentials ?? []).map((c) => short(c.id));
    const { credentials, privasysId } = useAuthStore.getState();
    const held = credentials.map(
        (c) => `${short(c.credentialId)} · ${c.rpId} · ${c.registeredAt ? new Date(c.registeredAt * 1000).toISOString().slice(0, 10) : '?'}`,
    );
    if (privasysId?.credentialId) {
        held.push(`${short(privasysId.credentialId)} · privasys.id meta-account`);
    }
    return (
        `Requested credential: ${requested.join(', ') || '(none listed)'}\n` +
        `Held on this device (${held.length}):\n${held.map((h) => `  ${h}`).join('\n') || '  (none)'}`
    );
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

export type VaultBatchFetch =
    | { kind: 'ok'; batch: VerifiedVaultBatch }
    /** Approved, replaced by a newer batch, or expired. */
    | { kind: 'gone' }
    /** The list does not hash to what the passkey would sign. */
    | { kind: 'refused'; reason: VaultBatchRefusal };

/**
 * Fetch a batch by its capability and verify it. Only a list that hashes to the
 * batch id comes back as `ok`. Throws when the identity provider cannot be reached.
 */
export async function fetchVaultBatch(batchId: string): Promise<VaultBatchFetch> {
    if (!isVaultBatchId(batchId)) return { kind: 'refused', reason: 'binding' };
    const res = await fetch(
        `${IDP_BASE}/fido2/vault-approval/batch/pending?challenge=${encodeURIComponent(batchId)}`,
    );
    if (res.status === 404) return { kind: 'gone' };
    if (!res.ok) throw new Error(`fetch vault batch failed (${res.status})`);
    try {
        return { kind: 'ok', batch: verifyVaultBatch(batchId, await res.json()) };
    } catch (e) {
        if (e instanceof VaultBatchRefused) return { kind: 'refused', reason: e.reason };
        return { kind: 'refused', reason: 'malformed' };
    }
}

/**
 * Approve a verified batch: one assertion over the list's own hash. The answer
 * carries no tokens: they go to the owner who began the batch.
 */
export async function approveVaultBatch(batch: VerifiedVaultBatch, credential: Credential): Promise<void> {
    const { publicKey } = batch.options;
    const assertion = await signVaultAssertion(IDP_ORIGIN, credential.keyAlias, credential.credentialId, {
        ...publicKey,
        rpId: publicKey.rpId || credential.serverRpId,
    });
    const res = await fetch(
        `${IDP_BASE}/fido2/vault-approval/batch/complete?challenge=${encodeURIComponent(batch.batchId)}`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(assertion) },
    );
    if (!res.ok) throw new Error(`approve failed (${res.status}): ${await res.text()}`);
    const done = (await res.json()) as { status?: string; count?: number };
    if (done.status !== 'approved' || done.count !== batch.entries.length) {
        throw new Error('approve failed: the answer does not cover the whole list');
    }
}

/**
 * Tell the identity provider the holder declines, so the initiator learns at
 * once rather than at the expiry. Best-effort: the capability is the authority,
 * as for reading it, and an identity provider without the route (404) or out of
 * reach changes nothing here, since the wallet has already hidden the request
 * and the request expires on its own.
 */
async function declineVault(path: string, challenge: string): Promise<void> {
    try {
        const res = await fetch(`${IDP_BASE}${path}?challenge=${encodeURIComponent(challenge)}`, { method: 'POST' });
        if (!res.ok && res.status !== 404) console.warn(`[vault-approvals] decline answered ${res.status}`);
    } catch (e) {
        console.warn('[vault-approvals] decline failed', e);
    }
}

export const declineVaultApproval = (vaultOp: string) => declineVault('/fido2/vault-approval/decline', vaultOp);
export const declineVaultBatch = (batchId: string) => declineVault('/fido2/vault-approval/batch/decline', batchId);

/**
 * An app's name, looked up by the id in its signed handle. Null when the control
 * plane does not know the app, or answers for a different one.
 */
export async function lookupVaultBatchAppName(appIdHex: string): Promise<string | null> {
    const id = dashedAppId(appIdHex);
    const app = await resolveApp(id).catch(() => null);
    if (!app || app.app_id?.toLowerCase() !== id) return null;
    return app.display_name || app.name || null;
}

/** A host as the control plane names it to anyone holding its id. */
export interface VaultBatchHost {
    /** Absent for a host a customer owns: its name is theirs, not published. */
    name?: string;
    region?: string;
    country?: string;
    /** The runtime release the host runs now (not the one being approved). */
    release?: string;
}

/**
 * Name the host whose /data key a batch moves, by the enclave id inside the
 * signed handle. Null when the control plane does not know that id.
 */
export async function lookupVaultBatchHost(enclaveIdHex: string): Promise<VaultBatchHost | null> {
    if (!/^[0-9a-f]{32}$/.test(enclaveIdHex)) return null;
    const enclaveId = dashedAppId(enclaveIdHex);
    const got = await publicApiGet<{
        id?: string;
        name?: string;
        region?: string;
        country?: string;
        os_release_tag?: string;
    }>(`/api/v1/enclaves/${enclaveId}/public`);
    if (!got || got.id?.toLowerCase() !== enclaveId) return null;
    const text = (v: unknown) => (typeof v === 'string' && v.length > 0 && v.length <= 80 ? v : undefined);
    return { name: text(got.name), region: text(got.region), country: text(got.country), release: text(got.os_release_tag) };
}

/**
 * The published release of the version an app's promotes name. Asked of the
 * control plane with the app id from the signed handle, so a version of any
 * other app is refused there. Null when it cannot say.
 */
export async function lookupVaultBatchVersion(appIdHex: string, versionId: string): Promise<ReleaseProvenance | null> {
    return fetchReleaseProvenance(dashedAppId(appIdHex), versionId).catch(() => null);
}

/**
 * Register the wallet's Expo push token with the IdP under a given wallet
 * session's identity. Called after each successful RP sign-in with THAT RP's
 * session, so every pairwise identity that owns vault keys can be pushed —
 * without the IdP learning any pairwise linkage it doesn't already have.
 */
export async function registerPushTokenWithIdp(
    walletSessionToken: string,
    expoPushToken: string,
    encPub = '',
    /** The IdP user id the session is for: names this phone's target on it. */
    userId?: string,
): Promise<void> {
    let deviceTag = '';
    if (userId) {
        try {
            deviceTag = await myDeviceTag(userId);
        } catch {
            /* registers untagged, as before */
        }
    }
    const res = await fetch(`${IDP_BASE}/push-token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer wallet:${walletSessionToken}`,
        },
        // enc_pub is the device's X25519 notification-sealing key; the
        // IdP seals app-notification payloads to it (empty keeps any
        // previously registered key).
        // device_tag keeps one target per phone of the holder; every phone is notified.
        body: JSON.stringify({ push_token: expoPushToken, enc_pub: encPub, ...(deviceTag ? { device_tag: deviceTag } : {}) }),
    });
    if (!res.ok) {
        throw new Error(`register push token failed (${res.status})`);
    }
}

// The set of capabilities seen this session — and the fetch/prune that turns
// them into the live `pending` list — now lives in stores/vaultApprovals, so
// the Home banner and the approvals screen share one reactive source. This
// module stays the thin transport layer (fetch/approve/resolve/push-token).
