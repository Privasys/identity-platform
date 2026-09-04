// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The report sender classifies its failures, because the modal says something
 * different for each: an unconfigured server and a rate limit both mean "copy
 * it and send it yourself", while a network error means "try again". A single
 * "it did not work" would leave the holder with no idea which applies.
 */

jest.mock('expo-constants', () => ({ __esModule: true, default: { expoConfig: { version: '1.4.1' } } }));
jest.mock('react-native', () => ({ Platform: { OS: 'ios' } }));

import { sendErrorReport, ReportSendError, REPORT_INBOX } from '@/services/error-report';

const originalFetch = global.fetch;

function respondWith(status: number) {
    const mock = jest.fn().mockResolvedValue({ ok: status >= 200 && status < 300, status });
    global.fetch = mock as unknown as typeof fetch;
    return mock;
}

afterEach(() => {
    global.fetch = originalFetch;
    jest.clearAllMocks();
});

describe('sendErrorReport', () => {
    it('posts the report the holder read, with the platform and version', async () => {
        const fetchMock = respondWith(202);

        await sendErrorReport({ message: 'boom', contact: ' me@example.com ', context: 'connect' });

        expect(fetchMock).toHaveBeenCalledTimes(1);
        const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
        expect(url).toBe('https://privasys.id/wallet/report');
        expect(init.method).toBe('POST');
        const body = JSON.parse(init.body as string);
        expect(body).toMatchObject({
            message: 'boom',
            contact: 'me@example.com',
            context: 'connect',
            platform: 'ios',
            version: '1.4.1',
        });
    });

    it('omits a contact the holder left blank rather than sending an empty one', async () => {
        const fetchMock = respondWith(202);

        await sendErrorReport({ message: 'boom', contact: '   ' });

        const body = JSON.parse((fetchMock.mock.calls[0] as [string, RequestInit])[1].body as string);
        expect(body.contact).toBeUndefined();
    });

    it.each([
        [503, 'unavailable'],
        [429, 'rateLimited'],
        [502, 'failed'],
        [400, 'failed'],
    ])('turns %d into the %s fallback', async (status, reason) => {
        respondWith(status as number);

        await expect(sendErrorReport({ message: 'boom' })).rejects.toMatchObject({
            name: 'ReportSendError',
            reason,
        });
    });

    it('reports a transport failure as a network error', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('offline')) as unknown as typeof fetch;

        await expect(sendErrorReport({ message: 'boom' })).rejects.toBeInstanceOf(ReportSendError);
        await expect(sendErrorReport({ message: 'boom' })).rejects.toMatchObject({ reason: 'network' });
    });

    // The address the modal shows the holder is the address the server mails.
    it('names the support inbox', () => {
        expect(REPORT_INBOX).toBe('support@privasys.org');
    });
});
