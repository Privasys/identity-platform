// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Recovery API client — calls the IdP recovery endpoints.
 *
 * Two flavours of auth:
 * - Wallet session token (`Bearer wallet:<token>`) — issued by FIDO2
 *   register/authenticate against privasys.id; used for management
 *   operations (regenerate phrase, manage guardians, manage devices).
 * - No auth — for the public phrase-status endpoint and the recovery
 *   begin/status/complete flow (entropy of the 24-word BIP39 phrase
 *   is sufficient on its own).
 */

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

async function idpFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${IDP_BASE}${path}`;
    const res = await fetch(url, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            ...options.headers,
        },
    });
    if (!res.ok) {
        const body = await res.json().catch(() => ({ error: res.statusText }));
        throw new Error(body.error || `Request failed: ${res.status}`);
    }
    return res.json();
}

function walletHeaders(walletSessionToken: string): HeadersInit {
    return { Authorization: `Bearer wallet:${walletSessionToken}` };
}

// Legacy bearer (JWT access token) — still used by guardian/device endpoints
// that have not been migrated to wallet-session auth yet.
function authHeaders(accessToken: string): HeadersInit {
    return { Authorization: `Bearer ${accessToken}` };
}

// ── Recovery phrase (BIP39 24-word) ─────────────────────────────────────

export interface RecoveryPhraseResult {
    /** Space-separated 24-word BIP39 phrase. Returned ONCE. */
    phrase: string;
    message?: string;
}

export interface RecoveryPhraseStatus {
    has_phrase: boolean;
    /** Back-compat fields from legacy /recovery/codes API. */
    has_codes?: boolean;
    remaining_codes?: number;
}

/**
 * Public — anyone can check whether a user has a recovery phrase set up.
 * (Returns just a boolean; no sensitive data.)
 */
export async function getRecoveryPhraseStatus(userId: string): Promise<RecoveryPhraseStatus> {
    return idpFetch(`/recovery/phrase/status?user_id=${encodeURIComponent(userId)}`, {
        method: 'GET',
    });
}

/** Authenticated — generate a new 24-word phrase (replaces any existing one). */
export async function regenerateRecoveryPhrase(walletSessionToken: string): Promise<RecoveryPhraseResult> {
    return idpFetch('/recovery/phrase/regenerate', {
        method: 'POST',
        headers: walletHeaders(walletSessionToken),
    });
}

/** Authenticated — delete the existing recovery phrase. */
export async function deleteRecoveryPhrase(walletSessionToken: string): Promise<{ status: string }> {
    return idpFetch('/recovery/phrase', {
        method: 'DELETE',
        headers: walletHeaders(walletSessionToken),
    });
}

// ── Guardians ───────────────────────────────────────────────────────────

export interface GuardianInfo {
    guardian_id: string;
    display_name: string;
    status: string;
}

export interface GuardiansResult {
    guardians: GuardianInfo[];
    threshold: number;
}

export async function listGuardians(accessToken: string): Promise<GuardiansResult> {
    return idpFetch('/guardians', {
        method: 'GET',
        headers: authHeaders(accessToken),
    });
}

export interface InviteGuardianResult {
    status: string;
    invite_token: string;
    expires_at: string;
    message: string;
}

export async function inviteGuardianByEmail(accessToken: string, guardianEmail: string, threshold: number, userName: string): Promise<InviteGuardianResult> {
    return idpFetch('/guardians/invite', {
        method: 'POST',
        headers: authHeaders(accessToken),
        body: JSON.stringify({ guardian_email: guardianEmail, threshold, user_name: userName }),
    });
}

export async function addGuardianByQR(accessToken: string, guardianId: string, threshold: number): Promise<{ status: string; message: string }> {
    return idpFetch('/guardians/add', {
        method: 'POST',
        headers: authHeaders(accessToken),
        body: JSON.stringify({ guardian_id: guardianId, threshold }),
    });
}

export async function acceptGuardianInviteByToken(accessToken: string, inviteToken: string): Promise<{ status: string; user_id: string }> {
    return idpFetch('/guardians/accept-invite', {
        method: 'POST',
        headers: authHeaders(accessToken),
        body: JSON.stringify({ invite_token: inviteToken }),
    });
}

export async function removeGuardian(accessToken: string, guardianId: string): Promise<{ status: string }> {
    return idpFetch(`/guardians?guardian_id=${encodeURIComponent(guardianId)}`, {
        method: 'DELETE',
        headers: authHeaders(accessToken),
    });
}

export interface GuardianInvite {
    user_id: string;
    display_name: string;
}

export async function listGuardianInvites(accessToken: string): Promise<{ invites: GuardianInvite[] }> {
    return idpFetch('/guardians/invites', {
        method: 'GET',
        headers: authHeaders(accessToken),
    });
}

export async function respondToGuardianInvite(accessToken: string, userId: string, accept: boolean): Promise<{ status: string }> {
    return idpFetch('/guardians/respond', {
        method: 'POST',
        headers: authHeaders(accessToken),
        body: JSON.stringify({ user_id: userId, accept }),
    });
}

export interface RecoveryRequestInfo {
    request_id: string;
    user_id: string;
    display_name: string;
}

export async function listRecoveryRequests(accessToken: string): Promise<{ requests: RecoveryRequestInfo[] }> {
    return idpFetch('/guardians/recovery-requests', {
        method: 'GET',
        headers: authHeaders(accessToken),
    });
}

export async function approveRecovery(accessToken: string, requestId: string, approved: boolean): Promise<{ status: string }> {
    return idpFetch('/guardians/approve', {
        method: 'POST',
        headers: authHeaders(accessToken),
        body: JSON.stringify({ request_id: requestId, approved }),
    });
}

export interface GuardianQRData {
    user_id: string;
    display_name: string;
}

export async function getGuardianQR(accessToken: string): Promise<GuardianQRData> {
    return idpFetch('/guardians/qr', {
        method: 'GET',
        headers: authHeaders(accessToken),
    });
}

// ── Devices ─────────────────────────────────────────────────────────────

export interface DeviceInfo {
    credential_id: string;
    aaguid: string;
    attestation_type: string;
    sign_count: number;
    created_at: string;
}

export async function listDevices(accessToken: string): Promise<{ devices: DeviceInfo[] }> {
    return idpFetch('/devices', {
        method: 'GET',
        headers: authHeaders(accessToken),
    });
}

export async function revokeDevice(accessToken: string, credentialId: string): Promise<{ status: string }> {
    return idpFetch(`/devices?credential_id=${encodeURIComponent(credentialId)}`, {
        method: 'DELETE',
        headers: authHeaders(accessToken),
    });
}

// ── Recovery flow ───────────────────────────────────────────────────────

export interface RecoveryBeginResult {
    request_id: string;
    user_id: string;
    status: string;
    guardians_required: number;
    guardians_approved: number;
    expires_at: string;
}

/**
 * Begin a recovery request using a 24-word BIP39 phrase.
 * Phrase is the only credential needed — no device attestation, no rate limit.
 */
export async function beginRecovery(recoveryPhrase: string): Promise<RecoveryBeginResult> {
    return idpFetch('/recovery/begin', {
        method: 'POST',
        body: JSON.stringify({ recovery_phrase: recoveryPhrase }),
    });
}

export interface RecoveryStatusResult {
    request_id: string;
    status: string;
    guardians_required: number;
    guardians_approved: number;
    expires_at: string;
}

export async function getRecoveryStatus(requestId: string): Promise<RecoveryStatusResult> {
    return idpFetch(`/recovery/status?request_id=${encodeURIComponent(requestId)}`, {
        method: 'GET',
    });
}

export async function completeRecovery(requestId: string): Promise<{ status: string; user_id: string; message: string }> {
    return idpFetch('/recovery/complete', {
        method: 'POST',
        body: JSON.stringify({ request_id: requestId }),
    });
}
