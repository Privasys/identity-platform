// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What a notification does by its type: silent work whenever it arrives, a
 * screen at once only for what the holder is waiting on, anything else on a
 * tap.
 */

jest.mock('react-native', () => ({
    Platform: { OS: 'ios' },
    AppState: { addEventListener: jest.fn() },
    Linking: { openURL: jest.fn() },
}));
jest.mock('expo-notifications', () => ({ setNotificationHandler: jest.fn() }));

const mockDeletion = jest.fn(async (_type: string) => undefined);
jest.mock('../services/account-deletion-events', () => ({
    DELETION_PUSH_TYPES: new Set(['account-deletion-scheduled']),
    handleDeletionPush: (t: string) => mockDeletion(t),
}));
jest.mock('../services/app-form', () => ({ APP_FORM_TYPE: 'app-form' }));
jest.mock('../services/app-message', () => ({ APP_MESSAGE_TYPE: 'app-message', appMessageLink: jest.fn(), readAppMessage: jest.fn(() => ({})) }));
jest.mock('../services/approval', () => ({ APPROVAL_TYPE: 'approval' }));
jest.mock('../services/attribute-approval-api', () => ({ fetchAttributeApproval: jest.fn() }));
jest.mock('../services/descriptor', () => ({ DEFAULT_RELAY_HOST: 'relay', fetchDescriptor: jest.fn() }));
const mockPullRelay = jest.fn(async () => undefined);
jest.mock('../services/device-sync', () => ({ pullRelay: () => mockPullRelay() }));
jest.mock('../services/drive-files', () => ({ driveRouteFor: jest.fn() }));
jest.mock('../services/drive-share-push', () => ({ fileDriveNotification: jest.fn() }));
const mockDismissHere = jest.fn(async (_key: string) => undefined);
jest.mock('../services/notification-dismiss', () => ({
    DISMISS_TYPE: 'notification-dismiss',
    dismissHere: (k: string) => mockDismissHere(k),
    notificationAnswered: jest.fn(),
}));
jest.mock('../services/notify-seal', () => ({ openSealedNotification: jest.fn() }));
const mockAnswer = jest.fn(async (_d: unknown) => true);
jest.mock('../services/push-bind', () => ({
    carriesBindChallenge: (d: Record<string, unknown>) => typeof d?.bind_nonce === 'string',
    answerBindChallenge: (d: unknown) => mockAnswer(d),
}));
jest.mock('../services/push-tray', () => ({ sweepTray: jest.fn() }));
jest.mock('../services/vault-approval-batch', () => ({ vaultBatchRouteName: (id: string) => `/vault-approvals/${id}` }));
jest.mock('../stores/app-messages', () => ({ dismissAppMessage: jest.fn(), readMessage: jest.fn(), useAppMessagesStore: { getState: () => ({}) } }));
const mockLock = { expectExemptPush: jest.fn(), setLaunchPushChecked: jest.fn() };
jest.mock('../stores/app-lock', () => ({ useAppLockStore: { getState: () => mockLock } }));
jest.mock('../stores/drive-notifications', () => ({ useDriveNotificationsStore: { getState: () => ({ decisions: [] }) } }));
jest.mock('../stores/guardian-requests', () => ({ useGuardianRequestsStore: { getState: () => ({ remember: jest.fn() }) } }));
const mockApprovals = { remember: jest.fn(), rememberBatch: jest.fn() };
jest.mock('../stores/vaultApprovals', () => ({ useVaultApprovalsStore: { getState: () => mockApprovals } }));
jest.mock('../utils/active-route', () => ({ isRouteActive: () => false }));

import type { Router } from 'expo-router';

import { authRequestPayload, dispatchPush } from '../services/push-router';

const router = { push: jest.fn(), navigate: jest.fn() };
const route = router as unknown as Router;

beforeEach(() => jest.clearAllMocks());

describe('silent work', () => {
    it('is done on arrival, with no screen', async () => {
        await dispatchPush({ type: 'notification-dismiss', key: 'k' }, route, false);
        await dispatchPush({ type: 'device-relay' }, route, false);
        await dispatchPush({ type: 'account-deletion-scheduled' }, route, false);
        expect(mockDismissHere).toHaveBeenCalledWith('k');
        expect(mockPullRelay).toHaveBeenCalledTimes(1);
        expect(mockDeletion).toHaveBeenCalledWith('account-deletion-scheduled');
        expect(router.push).not.toHaveBeenCalled();
    });
});

describe('a screen', () => {
    it('opens at once for a request the holder is waiting on', async () => {
        await dispatchPush({ type: 'vault-approval', vault_op: 'op' }, route, false);
        expect(mockApprovals.remember).toHaveBeenCalledWith('op');
        expect(mockLock.expectExemptPush).toHaveBeenCalled();
        expect(router.push).toHaveBeenCalledWith({ pathname: '/vault-approvals', params: { vault_op: 'op', source: 'push' } });
    });

    it('waits for the tap otherwise', async () => {
        await dispatchPush({ type: 'share-request' }, route, false);
        expect(router.push).not.toHaveBeenCalled();
        await dispatchPush({ type: 'share-request' }, route, true);
        expect(router.push).toHaveBeenCalledWith({ pathname: '/drive-requests', params: { source: 'push' } });
    });

    it('is not opened for a type the wallet does not know, even one named like a built-in', async () => {
        await dispatchPush({ type: 'constructor' }, route, true);
        await dispatchPush({ type: 'toString' }, route, true);
        await dispatchPush({ type: 'something-new' }, route, true);
        await dispatchPush({}, route, true);
        expect(router.push).not.toHaveBeenCalled();
        expect(router.navigate).not.toHaveBeenCalled();
    });
});

it('answers a binding challenge beside what the notification is about', async () => {
    await dispatchPush({ type: 'vault-approval', vault_op: 'op', bind_nonce: 'n' }, route, false);
    expect(mockAnswer).toHaveBeenCalledTimes(1);
    expect(router.push).toHaveBeenCalledTimes(1);
});

describe('a sign-in request', () => {
    it('opens the connect screen with what it carries', async () => {
        await dispatchPush({ type: 'auth-request', origin: 'https://app.example', sessionId: 's', rpId: 'app.example', extraAppHosts: '["b.example"]' }, route, false);
        const { payload } = router.push.mock.calls[0][0].params;
        expect(JSON.parse(payload)).toMatchObject({ sessionId: 's', rpId: 'app.example', extraAppHosts: ['b.example'] });
    });

    it('missing what it needs opens nothing', () => {
        expect(authRequestPayload({ type: 'auth-request', origin: 'o', rpId: 'r' })).toBeNull();
        expect(authRequestPayload({ type: 'voucher-request', appHost: 'h', rpId: 'r', sid: 's' })).toBeNull();
    });
});
