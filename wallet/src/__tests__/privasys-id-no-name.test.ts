// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * privasys.id holds no data about the holder: registering the wallet's own
 * account there sends no user name, whatever the profile holds.
 */

const mockRegister = jest.fn(async (..._a: unknown[]) => ({ sessionToken: 's', credentialId: 'c', userId: 'u' }));
const mockSetPrivasysId = jest.fn();

jest.mock('expo-crypto', () => ({
    CryptoDigestAlgorithm: { SHA256: 'SHA-256' },
    digestStringAsync: async () => 'ab'.repeat(32),
    getRandomBytes: () => new Uint8Array(8),
}));
jest.mock('../services/fido2', () => ({
    register: (...a: unknown[]) => mockRegister(...a),
    authenticate: jest.fn(),
}));
jest.mock('../services/identities', () => ({ syncIdentityIndex: jest.fn(async () => undefined) }));
jest.mock('@/stores/auth', () => ({
    useAuthStore: { getState: () => ({ privasysId: null, setPrivasysId: mockSetPrivasysId, credentials: [] }) },
}));
jest.mock('@/stores/profile', () => ({
    useProfileStore: {
        getState: () => ({
            profile: {
                pairwiseSeed: '11'.repeat(32),
                attributes: [{ key: 'name', value: 'Ada Lovelace' }],
            },
        }),
    },
}));

import { ensurePrivasysSession } from '@/services/privasys-id';

it('registers with no user name', async () => {
    await ensurePrivasysSession();
    expect(mockRegister).toHaveBeenCalledTimes(1);
    const [, , , userName] = mockRegister.mock.calls[0];
    expect(userName).toBe('');
    expect(JSON.stringify(mockRegister.mock.calls[0])).not.toContain('Ada');
});
