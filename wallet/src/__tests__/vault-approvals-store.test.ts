// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The pending vault approvals: what discovery lists is kept, not fetched again.
 */

const mockFetchOne = jest.fn();
const mockList = jest.fn();
jest.mock('@/services/vault-approval-api', () => ({
    declineVaultApproval: jest.fn(),
    declineVaultBatch: jest.fn(),
    fetchVaultApproval: (op: string) => mockFetchOne(op),
    fetchVaultBatch: jest.fn(),
    listVaultApprovals: (token: string) => mockList(token),
}));
jest.mock('@/services/notification-dismiss', () => ({ requestAnswered: jest.fn() }));
jest.mock('@/services/privasys-id', () => ({
    getPrivasysAccount: () => ({ sessionToken: 'session', sessionExpiresAt: Date.now() + 60_000 }),
}));

import { useVaultApprovalsStore } from '@/stores/vaultApprovals';

const request = (op: string, expires = 100) =>
    ({ vault_op: op, options: { publicKey: { challenge: op } }, summary: { operation: 'promote', handle: 'h', measurement: '' }, expires_at: expires }) as never;

beforeEach(() => {
    useVaultApprovalsStore.getState().clearAll();
    mockFetchOne.mockReset();
    mockList.mockReset();
});

it('keeps what discovery listed and fetches only the ops it did not list', async () => {
    mockFetchOne.mockImplementation(async (op: string) => (op === 'from-push' ? request(op, 50) : null));
    useVaultApprovalsStore.setState({ knownOps: ['from-push'] });
    mockList.mockResolvedValue([request('listed', 200)]);

    await useVaultApprovalsStore.getState().discover();

    expect(mockFetchOne.mock.calls.map((c) => c[0])).toEqual(['from-push']);
    expect(useVaultApprovalsStore.getState().pending.map((r) => r.vault_op)).toEqual(['listed', 'from-push']);
});

it('still fetches every known op when discovery fails', async () => {
    mockFetchOne.mockImplementation(async (op: string) => request(op));
    useVaultApprovalsStore.setState({ knownOps: ['a'] });
    mockList.mockRejectedValue(new Error('down'));
    jest.spyOn(console, 'warn').mockImplementation(() => undefined);

    await useVaultApprovalsStore.getState().discover();

    expect(mockFetchOne).toHaveBeenCalledWith('a');
    expect(useVaultApprovalsStore.getState().pending.map((r) => r.vault_op)).toEqual(['a']);
});
