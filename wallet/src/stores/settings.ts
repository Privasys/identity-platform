// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import * as SecureStore from '@/utils/storage';
import { create } from 'zustand';

export interface SettingsState {
    /** Biometric grace period in seconds. 0 = always prompt. */
    gracePeriodSec: number;

    setGracePeriod: (seconds: number) => void;
    hydrate: () => Promise<void>;
}

const STORE_KEY = 'v1-settings';
const GRACE_OPTIONS = [0, 15, 30, 60];

export { GRACE_OPTIONS };

export const useSettingsStore = create<SettingsState>((set, get) => ({
    gracePeriodSec: 30,

    setGracePeriod: (seconds) => {
        set({ gracePeriodSec: seconds });
        SecureStore.setItemAsync(STORE_KEY, JSON.stringify({ gracePeriodSec: seconds })).catch(
            console.error
        );
    },

    hydrate: async () => {
        const raw = await SecureStore.getItemAsync(STORE_KEY);
        if (!raw) return;
        try {
            const data = JSON.parse(raw);
            if (typeof data.gracePeriodSec === 'number' && GRACE_OPTIONS.includes(data.gracePeriodSec)) {
                set({ gracePeriodSec: data.gracePeriodSec });
            }
        } catch {
            // Corrupted — use defaults
        }
    }
}));
