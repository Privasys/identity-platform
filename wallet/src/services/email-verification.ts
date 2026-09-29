// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Proving an address the holder typed.
 *
 * An email is either imported from a provider that says it checked it, or it
 * is typed here, in which case nobody has checked anything. This is the second
 * case: privasys.id mails a code to the address, the holder types it back, and
 * what comes back is a receipt signed by privasys.id saying this account
 * proved this address.
 *
 * The receipt is kept as the attribute's evidence. privasys.id keeps nothing:
 * it holds the address only while the code is outstanding, so the wallet is
 * the only place the result lives.
 */

import { getPlatformToken } from '@/services/platform-token';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** How the check failed, so the screen can say something true about it. */
export type EmailVerifyFailure =
    | 'bad-address'     // not an address this server will mail
    | 'wrong-code'      // wrong, with tries left
    | 'expired'         // expired, used, or out of tries: ask for a new one
    | 'too-soon'        // a code was just sent
    | 'no-mail'         // this server cannot send mail at all
    | 'send-failed'     // the mail did not go
    | 'offline';        // the wallet could not reach privasys.id

export class EmailVerifyError extends Error {
    readonly reason: EmailVerifyFailure;
    /** Tries left on this code, when the server said. */
    readonly attemptsLeft?: number;
    /** Seconds to wait before asking for another code, when the server said. */
    readonly retryAfter?: number;

    constructor(reason: EmailVerifyFailure, message: string, extra: { attemptsLeft?: number; retryAfter?: number } = {}) {
        super(message);
        this.name = 'EmailVerifyError';
        this.reason = reason;
        this.attemptsLeft = extra.attemptsLeft;
        this.retryAfter = extra.retryAfter;
    }
}

export interface CodeSent {
    /** Unix seconds after which the code stops working. */
    expiresAt: number;
    /** Seconds before another code may be asked for. */
    resendAfter: number;
    /** How many digits to ask for. */
    codeLength: number;
}

export interface EmailVerified {
    /** The address as the server normalised it, which is what to store. */
    email: string;
    verifiedAt: number;
    /** The signed receipt. Audit evidence on the attribute, never shown to apps. */
    receipt: string;
}

async function post(path: string, body: unknown): Promise<Response> {
    const token = await getPlatformToken();
    return fetch(`${IDP_BASE}${path}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
}

/** Read the server's message, without letting a stray body become the error. */
async function errorBody(res: Response): Promise<{ error?: string; attempts_left?: number }> {
    try {
        return (await res.json()) as { error?: string; attempts_left?: number };
    } catch {
        return {};
    }
}

/** Ask for a code to be mailed to `email`. */
export async function sendEmailCode(email: string): Promise<CodeSent> {
    let res: Response;
    try {
        res = await post('/wallet/email/verify/begin', { email });
    } catch (e) {
        throw new EmailVerifyError('offline', e instanceof Error ? e.message : 'could not reach privasys.id');
    }
    if (res.ok) {
        const body = (await res.json()) as {
            expires_at?: number;
            resend_after?: number;
            code_length?: number;
        };
        return {
            expiresAt: body.expires_at ?? 0,
            resendAfter: body.resend_after ?? 60,
            codeLength: body.code_length ?? 6,
        };
    }
    const body = await errorBody(res);
    const message = body.error || `the code could not be sent (${res.status})`;
    if (res.status === 400) throw new EmailVerifyError('bad-address', message);
    if (res.status === 429) {
        const header = Number(res.headers.get('Retry-After'));
        throw new EmailVerifyError('too-soon', message, {
            retryAfter: Number.isFinite(header) && header > 0 ? header : undefined,
        });
    }
    if (res.status === 503) throw new EmailVerifyError('no-mail', message);
    throw new EmailVerifyError('send-failed', message);
}

/** Hand back the code the holder read, and take the receipt. */
export async function confirmEmailCode(email: string, code: string): Promise<EmailVerified> {
    let res: Response;
    try {
        res = await post('/wallet/email/verify/complete', { email, code: code.trim() });
    } catch (e) {
        throw new EmailVerifyError('offline', e instanceof Error ? e.message : 'could not reach privasys.id');
    }
    if (res.ok) {
        const body = (await res.json()) as { email?: string; verified_at?: number; receipt?: string };
        if (!body.receipt || !body.email) {
            throw new EmailVerifyError('send-failed', 'the server did not return a result');
        }
        return {
            email: body.email,
            verifiedAt: body.verified_at ?? Math.floor(Date.now() / 1000),
            receipt: body.receipt,
        };
    }
    const body = await errorBody(res);
    const message = body.error || `the code could not be checked (${res.status})`;
    // 410 covers expired, already used, and out of tries: in every one of them
    // the only way on is a new code, which is what the screen offers.
    if (res.status === 410) throw new EmailVerifyError('expired', message);
    if (res.status === 400) {
        throw new EmailVerifyError(
            body.attempts_left === undefined ? 'bad-address' : 'wrong-code',
            message,
            { attemptsLeft: body.attempts_left },
        );
    }
    throw new EmailVerifyError('send-failed', message);
}
