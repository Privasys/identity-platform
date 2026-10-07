// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// Storage is in-memory here, as in the other store tests.
const mockStorage: Record<string, string> = {};
jest.mock('@/utils/storage', () => ({
    getItemAsync: jest.fn(async (key: string) => mockStorage[key] ?? null),
    setItemAsync: jest.fn(async (key: string, value: string) => {
        mockStorage[key] = value;
    }),
    deleteItemAsync: jest.fn(async (key: string) => {
        delete mockStorage[key];
    }),
}));

import { useNotifyMutesStore } from '@/stores/notify-mutes';

const app = '11111111-2222-3333-4444-555555555555';

beforeEach(() => {
    for (const k of Object.keys(mockStorage)) delete mockStorage[k];
    useNotifyMutesStore.setState({ muted: [], hydrated: false });
});

describe('the wallet\'s record of silenced apps', () => {
    it('remembers a silenced app across a restart, whatever the case of its id', async () => {
        useNotifyMutesStore.getState().setMuted(app.toUpperCase(), true);
        expect(useNotifyMutesStore.getState().isMuted(app)).toBe(true);

        // A fresh launch reads it back.
        useNotifyMutesStore.setState({ muted: [], hydrated: false });
        await useNotifyMutesStore.getState().hydrate();
        expect(useNotifyMutesStore.getState().isMuted(app)).toBe(true);
    });

    it('hears from an app again, and keeps one entry per app', () => {
        const store = useNotifyMutesStore.getState();
        store.setMuted(app, true);
        store.setMuted(app, true);
        expect(useNotifyMutesStore.getState().muted).toEqual([app]);
        store.setMuted(app, false);
        expect(useNotifyMutesStore.getState().isMuted(app)).toBe(false);
    });

    it('starts from nothing after a wipe, and reads anything malformed as nothing', async () => {
        useNotifyMutesStore.getState().setMuted(app, true);
        useNotifyMutesStore.getState().clearAll();
        expect(useNotifyMutesStore.getState().muted).toEqual([]);
        expect(mockStorage['privasys.notify-mutes']).toBeUndefined();

        mockStorage['privasys.notify-mutes'] = '{"not":"a list"}';
        useNotifyMutesStore.setState({ muted: [], hydrated: false });
        await useNotifyMutesStore.getState().hydrate();
        expect(useNotifyMutesStore.getState().muted).toEqual([]);
    });
});
