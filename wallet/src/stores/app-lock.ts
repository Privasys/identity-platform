// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Whether the wallet is locked right now (services/app-lock). Not persisted:
 * every start begins locked when the lock is on, so there is nothing to keep.
 */

import { create } from 'zustand';

interface AppLockState {
    locked: boolean;
    /** When the wallet last went to the background, or null. */
    backgroundAt: number | null;
    lock: () => void;
    /** A fresh Face ID anywhere in the wallet is also an unlock. */
    unlock: () => void;
    /** Record when the wallet went to the background; null once it is back. */
    wentToBackground: (at: number | null) => void;
}

export const useAppLockStore = create<AppLockState>((set) => ({
    locked: false,
    backgroundAt: null,
    lock: () => set({ locked: true }),
    unlock: () => set({ locked: false }),
    wentToBackground: (at) => set({ backgroundAt: at }),
}));
