// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import * as SecureStore from '@/utils/storage';
import { create } from 'zustand';

export interface SettingsState {
    /** Biometric grace period in seconds. 0 = always prompt. */
    gracePeriodSec: number;
    /** Show the (in-progress) Drive tab. Off by default. */
    driveEnabled: boolean;

    setGracePeriod: (seconds: number) => void;
    setDriveEnabled: (enabled: boolean) => void;
    hydrate: () => Promise<void>;
}

const STORE_KEY = 'v1-settings';
const GRACE_OPTIONS = [0, 15, 30, 60];

export { GRACE_OPTIONS };

function persist(get: () => SettingsState) {
    const s = get();
    SecureStore.setItemAsync(
        STORE_KEY,
        JSON.stringify({ gracePeriodSec: s.gracePeriodSec, driveEnabled: s.driveEnabled })
    ).catch(console.error);
}

export const useSettingsStore = create<SettingsState>((set, get) => ({
    gracePeriodSec: 30,
    driveEnabled: false,

    setGracePeriod: (seconds) => {
        set({ gracePeriodSec: seconds });
        persist(get);
    },

    setDriveEnabled: (enabled) => {
        set({ driveEnabled: enabled });
        persist(get);
    },

    hydrate: async () => {
        const raw = await SecureStore.getItemAsync(STORE_KEY);
        if (!raw) return;
        try {
            const data = JSON.parse(raw);
            if (typeof data.gracePeriodSec === 'number' && GRACE_OPTIONS.includes(data.gracePeriodSec)) {
                set({ gracePeriodSec: data.gracePeriodSec });
            }
            if (typeof data.driveEnabled === 'boolean') {
                set({ driveEnabled: data.driveEnabled });
            }
        } catch {
            // Corrupted — use defaults
        }
    }
}));
