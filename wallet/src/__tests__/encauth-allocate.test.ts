// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The first step of a voucher: the wallet asks the identity provider which
 * subject the voucher must name. A tool that reaches many apps has a subject
 * per app, so the app is named in that request.
 */

jest.mock('../../modules/native-keys/src/index', () => ({ sign: jest.fn() }));

import { signAndUploadEncAuth } from '@/services/encauth';

describe('allocating a voucher', () => {
    it('names the app it is for', async () => {
        const calls: { url: string; init: RequestInit }[] = [];
        (global as any).fetch = jest.fn(async (url: string, init: RequestInit) => {
            calls.push({ url, init });
            return { ok: false, status: 400, text: async () => 'app_id required' };
        });
        await expect(
            signAndUploadEncAuth({
                walletSessionToken: 'session',
                keyId: 'key',
                clientId: 'privasys-explorer',
                deviceId: 'device',
                appId: '02104572ca2f41e8ae2d24c0294e6f5e',
                payload: {} as never,
            }),
        ).rejects.toThrow(/allocate encauth sid: 400/);
        expect(calls).toHaveLength(1);
        expect(calls[0].url).toMatch(/\/sessions\/encauth$/);
        expect(JSON.parse(String(calls[0].init.body))).toEqual({
            client_id: 'privasys-explorer',
            device_id: 'device',
            app_id: '02104572ca2f41e8ae2d24c0294e6f5e',
        });
        expect((calls[0].init.headers as Record<string, string>).Authorization).toBe('Bearer wallet:session');
    });
});
