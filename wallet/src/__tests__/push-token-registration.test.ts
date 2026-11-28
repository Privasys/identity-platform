// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Registering this phone's push token says whether it wants the number on its
 * icon, read from the holder's settings, and only once they have been read.
 */

const mockSettings = { hydrated: false, iconBadge: true };

jest.mock('../services/fido2', () => ({ signVaultAssertion: jest.fn() }));
jest.mock('../services/devices', () => ({ myDeviceTag: jest.fn(async () => 'tag') }));
jest.mock('../services/app-resolve', () => ({ resolveApp: jest.fn() }));
jest.mock('../services/push-bind', () => ({
    registrationProof: jest.fn(async () => ({ bind_pub: 'pub', issued_at: 1, bind_sig: 'sig' })),
    repeatWhenBound: jest.fn(),
}));
jest.mock('../stores/auth', () => ({ useAuthStore: { getState: () => ({}) } }));
jest.mock('../stores/settings', () => ({ useSettingsStore: { getState: () => mockSettings } }));

import { registerPushTokenWithIdp } from '../services/vault-approval-api';

let sent: Record<string, unknown>[] = [];

beforeEach(() => {
    sent = [];
    (global as any).fetch = jest.fn(async (_url: string, init: { body: string }) => {
        sent.push(JSON.parse(init.body));
        return { ok: true, status: 200, json: async () => ({ bound: true }) };
    });
});

it('says nothing about the icon before the settings are read', async () => {
    Object.assign(mockSettings, { hydrated: false, iconBadge: false });
    await registerPushTokenWithIdp('session', 'ExponentPushToken[me]', 'enc', 'user');
    expect(sent[0]).not.toHaveProperty('badge');
});

it('sends the holder\'s choice once they are read', async () => {
    Object.assign(mockSettings, { hydrated: true, iconBadge: false });
    await registerPushTokenWithIdp('session', 'ExponentPushToken[me]', 'enc', 'user');
    expect(sent[0]).toMatchObject({ push_token: 'ExponentPushToken[me]', badge: false });

    Object.assign(mockSettings, { hydrated: true, iconBadge: true });
    await registerPushTokenWithIdp('session', 'ExponentPushToken[me]', 'enc', 'user');
    expect(sent[1]).toMatchObject({ badge: true });
});
