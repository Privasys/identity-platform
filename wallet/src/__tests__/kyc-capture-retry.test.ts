// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Only an unreadable capture is worth retaking.
 *
 * The capture screen asks "retake the photo?" on exactly one failure: the
 * verifier read the image and could not make out the MRZ (HTTP 422). The rule
 * had been written inline as
 *
 *     e instanceof VerifierHttpError ? e.isUnreadableCapture
 *                                    : !(e instanceof VerifierHttpError)
 *
 * whose second branch is true by construction, so every transport failure — an
 * upload that died mid-write, an unreachable enclave, a malformed response —
 * offered a retake against a failure no camera can fix. A tester hit exactly
 * that on a real passport: the image never reached the verifier and the wallet
 * asked for another snapshot instead of saying so (2026-08-26).
 *
 * These cases are the rule. The transport ones are the regression.
 */

// No mocks: services/kyc-errors is a leaf module, which is the point of it
// living apart from kyc.ts. If this test ever needs a mock again, the taxonomy
// has grown a dependency it should not have.
import { isRetryableCapture, VerifierHttpError } from '@/services/kyc-errors';

describe('isRetryableCapture', () => {
    it('offers a retake when the verifier could not read the MRZ', () => {
        expect(isRetryableCapture(new VerifierHttpError(422, '{"error":"MRZ unreadable"}'))).toBe(true);
    });

    it.each([
        [400, 'bad request'],
        [401, 'unauthorised'],
        [403, 'gate refusal'],
        [404, 'wrong endpoint'],
        [413, 'payload too large'],
        [500, 'enclave error'],
        [503, 'trust anchors pending'],
    ])('does not offer a retake for HTTP %i (%s)', (status) => {
        expect(isRetryableCapture(new VerifierHttpError(status, ''))).toBe(false);
    });

    // The regression. Every one of these reached the "retake the photo" branch.
    it.each([
        ['a broken upload', new Error('Broken pipe (os error 32)')],
        ['an unreachable enclave', new Error('The identity verifier is unreachable.')],
        ['an interrupted call', new Error('The connection to the identity verifier was interrupted while uploading.')],
        ['a malformed response', new SyntaxError('Unexpected token < in JSON at position 0')],
        ['a rejected attestation', new Error('attestation verification failed')],
        ['a non-Error rejection', 'something went wrong'],
        ['nothing at all', undefined],
    ])('does not offer a retake for %s', (_label, thrown) => {
        expect(isRetryableCapture(thrown)).toBe(false);
    });
});
