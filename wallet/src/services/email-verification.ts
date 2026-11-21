// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Proving an address the holder typed.
 *
 * An email is either imported from a provider that says it checked it, or it
 * is typed here, in which case nobody has checked anything. This is the second
 * case: the Privasys Attribute Verifier mails a code to the address, the holder
 * types it back, and the verifier signs a proof that this holder proved this
 * address (services/attribute-verifier). The proof is kept on the attribute,
 * and disclosed afresh to an app at sign-in (services/attribute-proofs).
 *
 * The verifier keeps nothing: the code's state travels in the token it hands
 * back, so the wallet is the only place the result lives.
 */

import { attest, AttributeVerifierError, newCommitment, startMailCode, type AttributeProof } from '@/services/attribute-verifier';

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
    /** The address as the verifier normalised it, which is what to store. */
    email: string;
    verifiedAt: number;
    /** The verifier's signed proof, bound to this device. */
    proof: AttributeProof;
    /** The salt of the holder commitment the proof was made under. */
    salt: string;
}

/** The code in flight, per address: the verifier's token and the salt it was asked under. */
const pending = new Map<string, { mailToken: string; salt: string }>();

/** A failure to reach the verifier at all, as opposed to a refusal from it. */
function offline(e: unknown): boolean {
    return !(e instanceof AttributeVerifierError) || e.status === 0;
}

/** Ask for a code to be mailed to `email`. */
export async function sendEmailCode(email: string): Promise<CodeSent> {
    const { salt } = newCommitment();
    try {
        const r = await startMailCode(email, salt);
        pending.set(email.toLowerCase(), { mailToken: r.mailToken, salt });
        return { expiresAt: r.expiresAt, resendAfter: r.resendAfter, codeLength: r.codeLength };
    } catch (e) {
        if (offline(e)) throw new EmailVerifyError('offline', e instanceof Error ? e.message : 'could not reach the verifier');
        const err = e as AttributeVerifierError;
        if (err.status === 400) throw new EmailVerifyError('bad-address', err.message);
        if (err.status === 429) throw new EmailVerifyError('too-soon', err.message);
        if (err.status === 503) throw new EmailVerifyError('no-mail', err.message);
        throw new EmailVerifyError('send-failed', err.message);
    }
}

/** Hand back the code the holder read, and take the verifier's proof. */
export async function confirmEmailCode(email: string, code: string): Promise<EmailVerified> {
    const inFlight = pending.get(email.toLowerCase());
    if (!inFlight) throw new EmailVerifyError('expired', 'no code was asked for this address on this device');
    let proofs: AttributeProof[];
    try {
        proofs = await attest('mail_code', { email, code: code.trim(), mail_token: inFlight.mailToken }, inFlight.salt);
    } catch (e) {
        if (offline(e)) throw new EmailVerifyError('offline', e instanceof Error ? e.message : 'could not reach the verifier');
        const err = e as AttributeVerifierError;
        const left = err.body?.attempts_left;
        if (typeof left === 'number') throw new EmailVerifyError('wrong-code', err.message, { attemptsLeft: left });
        // Expired, already used, out of tries: the only way on is a new code.
        if (/expired|already used|too many|ask for a new one/i.test(err.message)) throw new EmailVerifyError('expired', err.message);
        throw new EmailVerifyError('send-failed', err.message);
    }
    const proof = proofs.find((p) => p.attr === 'email');
    if (!proof || typeof proof.value !== 'string') throw new EmailVerifyError('send-failed', 'the verifier did not return a proof');
    pending.delete(email.toLowerCase());
    return { email: proof.value, verifiedAt: Math.floor(Date.now() / 1000), proof, salt: inFlight.salt };
}
