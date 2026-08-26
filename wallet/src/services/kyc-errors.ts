// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Verifier failure taxonomy.
 *
 * Deliberately a leaf module with no imports: it lives apart from kyc.ts so the
 * rule deciding what the user is offered after a failed capture can be tested
 * on its own, without dragging the React Native runtime and three native
 * modules into a test that only needs an integer.
 */

/**
 * A non-2xx answer from the verifier enclave, carrying the status so a caller
 * can distinguish "the capture was unreadable, retry helps" (422) from a gate
 * refusal or transport failure, where retrying the same thing cannot help.
 */
export class VerifierHttpError extends Error {
    readonly status: number;
    readonly detail: string;
    constructor(status: number, body: string) {
        let detail = (body || '').slice(0, 300);
        try {
            const parsed = JSON.parse(body) as { error?: string };
            if (parsed?.error) detail = parsed.error;
        } catch {
            // not JSON: keep the raw snippet
        }
        super(`Identity verifier returned HTTP ${status}: ${detail}`);
        this.name = 'VerifierHttpError';
        this.status = status;
        this.detail = detail;
    }
    /** True when the failure is about the captured image, so a retake is the
     *  right remedy. Anything else needs a different action or a fix. */
    get isUnreadableCapture(): boolean {
        return this.status === 422;
    }
}

/**
 * A credential the endpoint requires could not be obtained on this device, so
 * the call was never made.
 *
 * Distinct from every other failure here in that nothing left the phone. The
 * endpoints that need a Wallet Instance Attestation are gated by the runtime,
 * which refuses an unexempt call before reading the request body; against a
 * body the size of a passport photo that refusal reaches the client as a
 * connection reset rather than a status, so the wallet checks first and says
 * what is actually missing.
 */
export class VerifierMissingCredentialError extends Error {
    /** The underlying enrolment failure, when one was recorded. */
    readonly reason: string | null;
    constructor(reason: string | null) {
        super(
            'This device could not prove it is a genuine Privasys Wallet, which the ' +
            'identity verifier requires before it will read a document' +
            (reason ? ` (${reason})` : '') +
            '.'
        );
        this.name = 'VerifierMissingCredentialError';
        this.reason = reason;
    }
}

/**
 * Is retaking the photo the right remedy for this failure?
 *
 * TRUE for exactly one case: the verifier read the image and could not make out
 * the MRZ (HTTP 422). Everything else — a gate refusal, a rejected attestation,
 * an unreachable enclave, an upload that died mid-write — is unaffected by a
 * better photo, and offering "retake" for it puts the user in a loop that
 * cannot succeed.
 *
 * This rule lived inline in the capture screen with its non-HTTP branch written
 * as `!(e instanceof VerifierHttpError)`, which is true by construction, so
 * every transport failure asked for another snapshot. A tester hit it on a real
 * passport: the image never reached the verifier and the wallet responded by
 * asking for another photo (2026-08-26).
 */
export function isRetryableCapture(e: unknown): boolean {
    return e instanceof VerifierHttpError && e.isUnreadableCapture;
}
