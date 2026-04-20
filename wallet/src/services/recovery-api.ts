// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Recovery API client — calls the IdP recovery endpoints.
 *
 * Endpoints:
 * - Email verification (send + verify OTP)
 * - Recovery codes (generate, check)
 * - Guardians (list, invite, remove, respond, approve)
 * - Devices (list, revoke)
 * - Recovery flow (begin, status, complete)
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

// ── Email verification ──────────────────────────────────────────────────

export async function sendVerificationEmail(email: string): Promise<{ verification_id: string }> {
    return idpFetch('/recovery/email/send', {
        method: 'POST',
        body: JSON.stringify({ email }),
    });
}

export async function verifyEmailCode(email: string, code: string): Promise<{ verification_id: string; verified: string }> {
    return idpFetch('/recovery/email/verify', {
        method: 'POST',
        body: JSON.stringify({ email, code }),
    });
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

// ── Guardians ───────────────────────────────────────────────────────────

export interface GuardianInfo {
    guardian_id: string;
    guardian_email: string;
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

export async function inviteGuardian(accessToken: string, guardianEmail: string, threshold: number): Promise<{ status: string }> {
    return idpFetch('/guardians', {
        method: 'POST',
        headers: authHeaders(accessToken),
        body: JSON.stringify({ guardian_email: guardianEmail, threshold }),
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
    user_email: string;
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
    user_email: string;
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

export async function beginRecovery(email: string, verificationId: string, recoveryCode: string): Promise<RecoveryBeginResult> {
    return idpFetch('/recovery/begin', {
        method: 'POST',
        body: JSON.stringify({ email, verification_id: verificationId, recovery_code: recoveryCode }),
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
