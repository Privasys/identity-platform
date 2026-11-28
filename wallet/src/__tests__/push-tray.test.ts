// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The pass over the notification tray when the wallet comes up or to the
 * front: challenges answered, stale requests cleared, the rest filed, and
 * approvals privasys.id no longer reports open cleared.
 */

jest.mock('react-native', () => ({ Platform: { OS: 'ios' } }));

const mockDismiss = jest.fn(async (_id: string) => undefined);
let mockPresented: { request: { identifier: string; content: { data: Record<string, unknown> } }; date: number }[] = [];
jest.mock('expo-notifications', () => ({
    setNotificationHandler: jest.fn(),
    getPresentedNotificationsAsync: jest.fn(async () => mockPresented),
    dismissNotificationAsync: (id: string) => mockDismiss(id),
}));

const mockAnswer = jest.fn(async (_data: unknown) => true);
jest.mock('../services/push-bind', () => ({
    carriesBindChallenge: (d: Record<string, unknown> | undefined) => typeof d?.bind_nonce === 'string',
    answerBindChallenge: (d: unknown) => mockAnswer(d),
}));

const mockFile = jest.fn(async (_data: unknown) => true);
jest.mock('../services/drive-share-push', () => ({
    isDriveShare: (d: Record<string, unknown> | undefined) => d?.type === 'share-request' || d?.type === 'share-decision',
    fileDriveNotification: (d: unknown) => mockFile(d),
}));

const mockGuardian = { remember: jest.fn() };
jest.mock('../stores/guardian-requests', () => ({ useGuardianRequestsStore: { getState: () => mockGuardian } }));

// privasys.id, asked on refresh, still has op-open and batch-open waiting.
const mockApprovals = {
    knownOps: [] as string[],
    batchIds: [] as string[],
    remember: jest.fn((op: string) => void mockApprovals.knownOps.push(op)),
    rememberBatch: jest.fn((id: string) => void mockApprovals.batchIds.push(id)),
    refresh: jest.fn(async () => {
        mockApprovals.knownOps = mockApprovals.knownOps.filter((op) => op === 'op-open');
    }),
    refreshBatches: jest.fn(async () => {
        mockApprovals.batchIds = mockApprovals.batchIds.filter((id) => id === 'batch-open');
    }),
};
jest.mock('../stores/vaultApprovals', () => ({ useVaultApprovalsStore: { getState: () => mockApprovals } }));

import { STALE_AFTER_MS } from '../services/notification-dismiss';
import { sweepTray } from '../services/push-tray';

const shown = (identifier: string, data: Record<string, unknown>, age = 0) => ({
    request: { identifier, content: { data } },
    date: Date.now() - age,
});
const dismissed = () => mockDismiss.mock.calls.map(([id]) => id);

beforeEach(() => {
    jest.clearAllMocks();
    mockPresented = [];
    mockApprovals.knownOps = [];
    mockApprovals.batchIds = [];
});

it('answers the first challenge that succeeds, even on a notification it then clears', async () => {
    mockPresented = [
        shown('old', { type: 'auth-request', bind_nonce: 'n1' }, STALE_AFTER_MS + 1000),
        shown('new', { type: 'auth-request', bind_nonce: 'n2' }),
    ];
    await sweepTray();
    expect(mockAnswer).toHaveBeenCalledTimes(1);
    expect(mockAnswer).toHaveBeenCalledWith(expect.objectContaining({ bind_nonce: 'n1' }));
    expect(dismissed()).toEqual(['old']);
});

it('tries the next challenge when one fails', async () => {
    mockAnswer.mockRejectedValueOnce(new Error('offline'));
    mockPresented = [
        shown('a', { type: 'auth-request', bind_nonce: 'n1' }),
        shown('b', { type: 'auth-request', bind_nonce: 'n2' }),
    ];
    await sweepTray();
    expect(mockAnswer).toHaveBeenCalledTimes(2);
});

it('clears a stale request without filing it', async () => {
    mockPresented = [shown('stale', { type: 'vault-approval', vault_op: 'op-old' }, STALE_AFTER_MS + 1000)];
    await sweepTray();
    expect(dismissed()).toEqual(['stale']);
    expect(mockApprovals.remember).not.toHaveBeenCalled();
    expect(mockApprovals.refresh).not.toHaveBeenCalled();
});

it('files what it finds, then clears only the approvals privasys.id no longer reports open', async () => {
    mockPresented = [
        shown('open', { type: 'vault-approval', vault_op: 'op-open' }),
        shown('closed', { type: 'vault-approval', vault_op: 'op-closed' }),
        shown('batch-open', { type: 'vault-approval-batch', batch_id: 'batch-open' }),
        shown('batch-closed', { type: 'vault-approval-batch', batch_id: 'batch-closed' }),
        shown('guardian', { type: 'recovery-request' }),
        shown('share', { type: 'share-request', sealed: 's' }),
    ];
    await sweepTray();
    expect(mockApprovals.remember.mock.calls.map(([op]) => op)).toEqual(['op-open', 'op-closed']);
    expect(mockApprovals.rememberBatch.mock.calls.map(([id]) => id)).toEqual(['batch-open', 'batch-closed']);
    expect(mockGuardian.remember).toHaveBeenCalledTimes(1);
    expect(mockFile).toHaveBeenCalledWith(expect.objectContaining({ type: 'share-request' }));
    expect(dismissed().sort()).toEqual(['batch-closed', 'closed']);
});

it('asks privasys.id nothing when no approval is in the tray', async () => {
    mockPresented = [shown('guardian', { type: 'recovery-request' })];
    await sweepTray();
    expect(mockApprovals.refresh).not.toHaveBeenCalled();
    expect(dismissed()).toEqual([]);
});
