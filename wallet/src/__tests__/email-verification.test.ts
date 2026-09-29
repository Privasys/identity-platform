// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// The token helper pulls in the FIDO2 stack; the calls themselves are the test.
jest.mock('@/services/platform-token', () => ({
    getPlatformToken: jest.fn().mockResolvedValue('platform-token'),
}));

import { confirmEmailCode, sendEmailCode, EmailVerifyError } from '@/services/email-verification';

const realFetch = global.fetch;

/** Answer the next call with this status and body. */
function answer(status: number, body: unknown, headers: Record<string, string> = {}) {
    global.fetch = jest.fn().mockResolvedValue({
        ok: status >= 200 && status < 300,
        status,
        headers: { get: (k: string) => headers[k] ?? null },
        json: async () => body,
    }) as unknown as typeof fetch;
}

afterEach(() => {
    global.fetch = realFetch;
});

describe('asking for a code', () => {
    it('reads back when it expires and when another may be asked for', async () => {
        answer(200, { expires_at: 1234, resend_after: 60, code_length: 6 });
        await expect(sendEmailCode('alice@example.com')).resolves.toEqual({
            expiresAt: 1234,
            resendAfter: 60,
            codeLength: 6,
        });
    });

    it('separates an address the server will not mail from a code just sent', async () => {
        answer(400, { error: 'that is not an email address' });
        await expect(sendEmailCode('nope')).rejects.toMatchObject({ reason: 'bad-address' });

        answer(429, { error: 'wait' }, { 'Retry-After': '45' });
        await expect(sendEmailCode('alice@example.com')).rejects.toMatchObject({
            reason: 'too-soon',
            retryAfter: 45,
        });

        answer(503, { error: 'no mail here' });
        await expect(sendEmailCode('alice@example.com')).rejects.toMatchObject({ reason: 'no-mail' });

        answer(502, { error: 'graph is down' });
        await expect(sendEmailCode('alice@example.com')).rejects.toMatchObject({ reason: 'send-failed' });
    });

    it('calls a failure to reach privasys.id what it is', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('network down')) as unknown as typeof fetch;
        await expect(sendEmailCode('alice@example.com')).rejects.toMatchObject({ reason: 'offline' });
    });
});

describe('handing back the code', () => {
    it('returns the address as the server normalised it, with the receipt', async () => {
        answer(200, { email: 'alice@example.com', verified_at: 99, receipt: 'jwt' });
        await expect(confirmEmailCode('ALICE@example.com', ' 123456 ')).resolves.toEqual({
            email: 'alice@example.com',
            verifiedAt: 99,
            receipt: 'jwt',
        });
    });

    it('refuses a success that carries no receipt', async () => {
        answer(200, { email: 'alice@example.com', verified_at: 99 });
        await expect(confirmEmailCode('alice@example.com', '123456')).rejects.toBeInstanceOf(EmailVerifyError);
    });

    it('tells a wrong code from one that is gone', async () => {
        answer(400, { error: 'that code is not right', attempts_left: 3 });
        await expect(confirmEmailCode('alice@example.com', '000000')).rejects.toMatchObject({
            reason: 'wrong-code',
            attemptsLeft: 3,
        });

        // Expired, already used, or out of tries: all one answer, because the
        // only way on from any of them is a new code.
        answer(410, { error: 'that code has expired' });
        await expect(confirmEmailCode('alice@example.com', '000000')).rejects.toMatchObject({
            reason: 'expired',
        });
    });
});
