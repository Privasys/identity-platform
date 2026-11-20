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
    /**
     * A tapped push is on its way to a screen that opens without the unlock
     * (services/app-lock lockExempt): when it was tapped, or null. Until the
     * screen is up, the lock waits instead of asking for Face ID, or the
     * holder would look once to unlock and again to approve.
     */
    exemptPushAt: number | null;
    expectExemptPush: () => void;
    clearExemptPush: () => void;
    /** The push that launched the wallet, if any, has been looked for. */
    launchPushChecked: boolean;
    setLaunchPushChecked: () => void;
}

export const useAppLockStore = create<AppLockState>((set) => ({
    locked: false,
    backgroundAt: null,
    lock: () => set({ locked: true }),
    unlock: () => set({ locked: false }),
    wentToBackground: (at) => set({ backgroundAt: at }),
    exemptPushAt: null,
    expectExemptPush: () => set({ exemptPushAt: Date.now() }),
    clearExemptPush: () => set({ exemptPushAt: null }),
    launchPushChecked: false,
    setLaunchPushChecked: () => set({ launchPushChecked: true }),
}));
