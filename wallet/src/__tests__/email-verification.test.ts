// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// The verifier client is the network here; what this module adds is turning
// its answers into reasons the screen can say something true about.
const mockStart = jest.fn();
const mockAttest = jest.fn();
jest.mock('@/services/attribute-verifier', () => ({
    // Defined here: the imports below are hoisted above anything declared in
    // this file, and the factory runs when they are.
    AttributeVerifierError: class extends Error {
        status: number;
        body: Record<string, unknown> | null;
        constructor(s: number, message: string, b: Record<string, unknown> | null = null) {
            super(message);
            this.status = s;
            this.body = b;
        }
    },
    newCommitment: () => ({ salt: 'c2FsdA', commitment: 'commit' }),
    startMailCode: (...a: unknown[]) => mockStart(...a),
    attest: (...a: unknown[]) => mockAttest(...a),
}));

import { AttributeVerifierError } from '@/services/attribute-verifier';
import { confirmEmailCode, sendEmailCode } from '@/services/email-verification';

const MockVerifierError = AttributeVerifierError as unknown as new (
    status: number,
    message: string,
    body?: Record<string, unknown> | null,
) => Error;

const sent = { mailToken: 'mt', expiresAt: 1234, codeLength: 6, maxAttempts: 5, resendAfter: 60 };

beforeEach(() => {
    mockStart.mockReset();
    mockAttest.mockReset();
});

describe('asking for a code', () => {
    it('reads back when it expires and when another may be asked for', async () => {
        mockStart.mockResolvedValue(sent);
        await expect(sendEmailCode('alice@example.com')).resolves.toEqual({ expiresAt: 1234, resendAfter: 60, codeLength: 6 });
    });

    it('separates an address the verifier will not mail from a code just sent', async () => {
        mockStart.mockRejectedValueOnce(new MockVerifierError(400, 'that is not an email address'));
        await expect(sendEmailCode('nope')).rejects.toMatchObject({ reason: 'bad-address' });
        mockStart.mockRejectedValueOnce(new MockVerifierError(429, 'wait'));
        await expect(sendEmailCode('alice@example.com')).rejects.toMatchObject({ reason: 'too-soon' });
        mockStart.mockRejectedValueOnce(new MockVerifierError(503, 'no mail here'));
        await expect(sendEmailCode('alice@example.com')).rejects.toMatchObject({ reason: 'no-mail' });
        mockStart.mockRejectedValueOnce(new MockVerifierError(502, 'the code could not be sent'));
        await expect(sendEmailCode('alice@example.com')).rejects.toMatchObject({ reason: 'send-failed' });
    });

    it('calls a failure to reach the verifier what it is', async () => {
        mockStart.mockRejectedValueOnce(new Error('network down'));
        await expect(sendEmailCode('alice@example.com')).rejects.toMatchObject({ reason: 'offline' });
        mockStart.mockRejectedValueOnce(new MockVerifierError(0, 'not the published build'));
        await expect(sendEmailCode('alice@example.com')).rejects.toMatchObject({ reason: 'offline' });
    });
});

describe('handing back the code', () => {
    it('returns the address as the verifier normalised it, with its proof', async () => {
        mockStart.mockResolvedValue(sent);
        await sendEmailCode('Alice@Example.com');
        const proof = { attr: 'email', value: 'alice@example.com', method: 'proven', source: 'privasys_mail', label: null, proof: 'jws' };
        mockAttest.mockResolvedValue([proof]);
        const r = await confirmEmailCode('Alice@Example.com', ' 123456 ');
        expect(r).toMatchObject({ email: 'alice@example.com', proof, salt: 'c2FsdA' });
        // The code is trimmed, sent with the verifier's own token, under the salt it was asked with.
        expect(mockAttest).toHaveBeenCalledWith('mail_code', { email: 'Alice@Example.com', code: '123456', mail_token: 'mt' }, 'c2FsdA');
    });

    it('says how many tries are left after a wrong code', async () => {
        mockStart.mockResolvedValue(sent);
        await sendEmailCode('alice@example.com');
        mockAttest.mockRejectedValue(new MockVerifierError(400, 'wrong code', { attempts_left: 3 }));
        await expect(confirmEmailCode('alice@example.com', '000000')).rejects.toMatchObject({ reason: 'wrong-code', attemptsLeft: 3 });
    });

    it('asks for a new code when this one is spent', async () => {
        mockStart.mockResolvedValue(sent);
        await sendEmailCode('alice@example.com');
        mockAttest.mockRejectedValue(new MockVerifierError(400, 'the code has expired; ask for a new one'));
        await expect(confirmEmailCode('alice@example.com', '000000')).rejects.toMatchObject({ reason: 'expired' });
    });

    it('asks for a new code when none was asked for on this device', async () => {
        await expect(confirmEmailCode('nobody@example.com', '000000')).rejects.toMatchObject({ reason: 'expired' });
    });
});
