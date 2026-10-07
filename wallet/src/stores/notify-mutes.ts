// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Which apps this holder has silenced, as the wallet remembers it.
 *
 * privasys.id is what enforces a mute (see services/notify-mutes). This list
 * is only how Service Details draws its switch without asking privasys.id,
 * which would need a fresh ceremony, and so a Face ID prompt, every time the
 * screen opened. If the two disagree (a recovered phone, a rotated key on the
 * server) the switch shows the app as heard, and turning it off again puts
 * both back in step.
 */

import { create } from 'zustand';

import * as SecureStore from '@/utils/storage';

const STORE_KEY = 'privasys.notify-mutes';

interface NotifyMutesState {
    /** Attested app ids (dashed, lowercase) the holder silenced. */
    muted: string[];
    hydrated: boolean;
    hydrate: () => Promise<void>;
    isMuted: (appId: string) => boolean;
    setMuted: (appId: string, muted: boolean) => void;
    clearAll: () => void;
}

export const useNotifyMutesStore = create<NotifyMutesState>((set, get) => ({
    muted: [],
    hydrated: false,

    hydrate: async () => {
        if (get().hydrated) return;
        try {
            const raw = await SecureStore.getItemAsync(STORE_KEY);
            const parsed = raw ? (JSON.parse(raw) as unknown) : [];
            set({
                muted: Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [],
                hydrated: true,
            });
        } catch {
            set({ hydrated: true });
        }
    },

    isMuted: (appId) => get().muted.includes(appId.toLowerCase()),

    setMuted: (appId, muted) => {
        const id = appId.toLowerCase();
        const rest = get().muted.filter((x) => x !== id);
        const next = muted ? [...rest, id] : rest;
        set({ muted: next });
        SecureStore.setItemAsync(STORE_KEY, JSON.stringify(next)).catch(() => {});
    },

    clearAll: () => {
        set({ muted: [] });
        SecureStore.deleteItemAsync(STORE_KEY).catch(() => {});
    },
}));
