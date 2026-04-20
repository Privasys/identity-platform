// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Recovery API client — calls the IdP recovery endpoints.
 *
 * Endpoints:
 * - Recovery codes (generate, check, delete)
 * - Guardians (list, invite by email, add by QR, accept invite, remove, respond, approve)
 * - Devices (list, revoke)
 * - Recovery flow (begin, status, complete)
 * - Guardian QR (get own QR data)
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

function authHeaders(accessToken: string): HeadersInit {
    return { Authorization: `Bearer ${accessToken}` };
}

// ── Recovery codes ──────────────────────────────────────────────────────

export interface RecoveryCodesResult {
    codes: string[];
    message: string;
}

export async function generateRecoveryCodes(accessToken: string): Promise<RecoveryCodesResult> {
    return idpFetch('/recovery/codes', {
        method: 'POST',
        headers: authHeaders(accessToken),
    });
}

export interface RecoveryCodesStatus {
    has_codes: boolean;
    remaining_codes: number;
}

export async function checkRecoveryCodes(accessToken: string): Promise<RecoveryCodesStatus> {
    return idpFetch('/recovery/codes', {
        method: 'GET',
        headers: authHeaders(accessToken),
    });
}

export async function deleteRecoveryCodes(accessToken: string): Promise<{ status: string }> {
    return idpFetch('/recovery/codes', {
        method: 'DELETE',
        headers: authHeaders(accessToken),
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

export async function beginRecovery(
    recoveryCode: string,
    devicePublicKey: string,  // base64 uncompressed P-256 (65 bytes: 0x04 || X || Y)
    deviceSignature: string,  // base64 ASN.1/DER ECDSA signature over SHA-256(recovery_code || timestamp)
    timestamp: string,        // RFC 3339
): Promise<RecoveryBeginResult> {
    return idpFetch('/recovery/begin', {
        method: 'POST',
        body: JSON.stringify({
            recovery_code: recoveryCode,
            device_public_key: devicePublicKey,
            device_signature: deviceSignature,
            timestamp,
        }),
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
