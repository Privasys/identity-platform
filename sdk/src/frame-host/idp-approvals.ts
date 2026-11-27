// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * Approvals that run only on the identity provider's own pages: a sign-in
 * another device started (RFC 8628), and an operation someone started.
 */

import type { AuthUIConfig } from '../ui';
import { b64urlJson } from './tokens';

/** A sign-in another device started and waits on (RFC 8628). */
export interface DeviceRequest {
    sessionId: string;
    clientId: string;
    appName: string;
    rpId: string;
    brokerUrl?: string;
    /** The wallet link of the request, as the identity provider made it. */
    qrPayload: string;
    requestedAttributes?: string[];
}

/**
 * Reads a pending device request from the identity provider. Everything the
 * ceremony needs is in the wallet link the request was created with: the
 * request's own session, the app that asked and what it asked for.
 */
export async function lookupDeviceRequest(idpBase: string, userCode: string): Promise<DeviceRequest> {
    const resp = await fetch(`${idpBase}/device/lookup?user_code=${encodeURIComponent(userCode)}`, { cache: 'no-store' });
    if (!resp.ok) throw new Error('This code is invalid or has expired');
    const data = await resp.json();
    if (data.status !== 'pending') throw new Error('This request has already been answered');
    const decoded = b64urlJson(new URL(String(data.qr_payload)).searchParams.get('p') ?? '');
    if (!decoded) throw new Error('This request cannot be approved here');
    const text = (v: unknown): string => (typeof v === 'string' ? v : '');
    const sessionId = text(decoded.sessionId);
    const clientId = text(decoded.clientId);
    if (!sessionId || !clientId) throw new Error('This request cannot be approved here');
    return {
        sessionId,
        clientId,
        appName: text(decoded.appName) || text(data.client_name) || clientId,
        rpId: text(decoded.rpId) || globalThis.location.hostname,
        ...(text(decoded.brokerUrl) ? { brokerUrl: text(decoded.brokerUrl) } : {}),
        qrPayload: String(data.qr_payload),
        ...(Array.isArray(decoded.requestedAttributes)
            ? { requestedAttributes: decoded.requestedAttributes.map(String) }
            : {}),
    };
}

/** An operation to approve, as the page passed it. */
export interface OperationRequest {
    walletLink: string;
    passkey: boolean;
    /** Answers the operation's status: `approved`, `declined` or `gone`. */
    statusUrl: string;
    /** Declines the operation (POST, 204). */
    declineUrl: string;
    /** What the gate says when it ends each way. */
    messages: { approved: string; declined: string; expired: string };
}

/** The wallet links an operation approval may carry: the production wallet's
 *  scheme, or a dev or preview build's. */
export const OPERATION_WALLET_LINK = /^privasys-wallet(-dev|-preview)?:\/\/[a-z-]+\?[A-Za-z0-9_=%&.-]+$/;

/** An address on this frame's own origin (the identity provider's), or nothing. */
export function ownOriginUrl(raw: unknown): string | undefined {
    if (typeof raw !== 'string' || raw.length > 2048) return undefined;
    try {
        const u = new URL(raw, globalThis.location.origin);
        return u.origin === globalThis.location.origin ? u.href : undefined;
    } catch {
        return undefined;
    }
}

/** A line of the page's copy: plain text, capped. */
export function sanitiseLine(raw: unknown, fallback: string): string {
    return typeof raw === 'string' && raw.trim() ? raw.trim().slice(0, 200) : fallback;
}

export function sanitiseOperation(raw: unknown): OperationRequest | undefined {
    const o = raw as {
        walletLink?: unknown; passkey?: unknown; statusUrl?: unknown; declineUrl?: unknown;
        messages?: { approved?: unknown; declined?: unknown; expired?: unknown };
    } | null | undefined;
    if (!o || typeof o.walletLink !== 'string' || !OPERATION_WALLET_LINK.test(o.walletLink)) return undefined;
    const statusUrl = ownOriginUrl(o.statusUrl);
    const declineUrl = ownOriginUrl(o.declineUrl);
    if (!statusUrl || !declineUrl) return undefined;
    const m = o.messages ?? {};
    return {
        walletLink: o.walletLink,
        passkey: o.passkey === true,
        statusUrl,
        declineUrl,
        messages: {
            approved: sanitiseLine(m.approved, 'You can close this tab.'),
            declined: sanitiseLine(m.declined, 'You can close this tab.'),
            expired: sanitiseLine(m.expired, 'This approval has expired.'),
        },
    };
}

/** Waits until the operation's status says it is approved. */
export async function waitOperation(op: OperationRequest, timeoutMs = 300_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const resp = await fetch(op.statusUrl, { cache: 'no-store' });
        const data = resp.ok ? await resp.json().catch(() => null) : null;
        if (data?.status === 'approved') return;
        if (data?.status === 'declined') throw new Error('The approval was declined.');
        if (data?.status === 'gone') throw new Error(op.messages.expired);
        await new Promise((r) => setTimeout(r, 1500));
    }
    throw new Error(op.messages.expired);
}

/**
 * How the gate ends a device request: it stays on the outcome, and the
 * holder may deny the request from it.
 */
export function deviceGate(userCode: string): Pick<AuthUIConfig, 'finalScreen' | 'decline'> {
    return {
        finalScreen: { title: 'Approved', message: 'Your device continues on its own. You can close this tab.' },
        decline: {
            label: 'Not me, deny',
            title: 'Request denied',
            message: 'You rejected this sign-in request. You can close this tab.',
            run: async () => {
                const resp = await fetch(`${globalThis.location.origin}/device/deny`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_code: userCode }),
                });
                if (!resp.ok) throw new Error('this request is no longer open');
            },
        },
    };
}

/**
 * The gate of an operation approval: the wallet link, the passkey offer
 * (the page runs the passkey itself), the wait on the operation's status,
 * and the outcomes in the page's own words.
 */
export function operationGate(
    operation: OperationRequest,
    parentOrigin: string,
): Pick<AuthUIConfig, 'finalScreen' | 'decline' | 'operationApproval'> {
    return {
        finalScreen: { title: 'Approved', message: operation.messages.approved },
        decline: {
            label: 'Not me, decline',
            title: 'Declined',
            message: operation.messages.declined,
            run: async () => {
                const resp = await fetch(operation.declineUrl, { method: 'POST' });
                if (resp.status !== 204) throw new Error('this approval is no longer open');
            },
        },
        operationApproval: {
            walletLink: operation.walletLink,
            ...(operation.passkey
                ? { onPasskey: () => window.parent.postMessage({ type: 'privasys:operation:passkey' }, parentOrigin) }
                : {}),
            wait: () => waitOperation(operation),
        },
    };
}

/** Waits until the identity provider says a session is authenticated. */
export async function waitAuthenticated(pollUrl: string, timeoutMs = 120_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const resp = await fetch(pollUrl, { cache: 'no-store' });
        if (!resp.ok) throw new Error(`poll failed: ${resp.status}`);
        const data = await resp.json().catch(() => null);
        if (data?.authenticated) return;
        await new Promise((r) => setTimeout(r, 1500));
    }
    throw new Error('The request timed out');
}
