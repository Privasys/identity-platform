// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import * as SecureStore from '@/utils/storage';
import { create } from 'zustand';

/** A previously verified and trusted enclave app. */
export interface TrustedApp {
    rpId: string;
    origin: string;
    /** Expected MRENCLAVE (SGX) or empty (TDX). */
    mrenclave?: string;
    /** Expected MRTD (TDX) or empty (SGX). */
    mrtd?: string;
    /** Code hash from the last verification. */
    codeHash?: string;
    /** Config Merkle root from the last verification. */
    configRoot?: string;
    /** TEE type: 'sgx' | 'tdx'. */
    teeType: 'sgx' | 'tdx';
    /** Epoch seconds of last successful attestation verification. */
    lastVerified: number;
    /** Credential ID registered with this app. */
    credentialId: string;
}

export interface TrustedAppsState {
    apps: TrustedApp[];

    addOrUpdate: (app: TrustedApp) => void;
    remove: (rpId: string) => void;
    getApp: (rpId: string) => TrustedApp | undefined;
    /** Check if an app's attestation matches what we last verified. */
    isAttestationMatch: (
        rpId: string,
        measurements: { mrenclave?: string; mrtd?: string; codeHash?: string; configRoot?: string }
    ) => boolean;
    hydrate: () => Promise<void>;
}

const STORE_KEY = 'v1-trusted-apps';

export const useTrustedAppsStore = create<TrustedAppsState>((set, get) => ({
    apps: [],

    addOrUpdate: (app) => {
        set((s) => {
            const existing = s.apps.findIndex((a) => a.rpId === app.rpId);
            if (existing >= 0) {
                const updated = [...s.apps];
                updated[existing] = app;
                return { apps: updated };
            }
            return { apps: [...s.apps, app] };
        });
        persist(get());
    },

    remove: (rpId) => {
        set((s) => ({ apps: s.apps.filter((a) => a.rpId !== rpId) }));
        persist(get());
    },

    getApp: (rpId) => get().apps.find((a) => a.rpId === rpId),

    isAttestationMatch: (rpId, measurements) => {
        const app = get().apps.find((a) => a.rpId === rpId);
        if (!app) return false;
        if (app.teeType === 'sgx') {
            return (
                app.mrenclave === measurements.mrenclave &&
                app.codeHash === measurements.codeHash &&
                app.configRoot === measurements.configRoot
            );
        }
        // TDX
        return (
            app.mrtd === measurements.mrtd &&
            app.codeHash === measurements.codeHash &&
            app.configRoot === measurements.configRoot
        );
    },

    hydrate: async () => {
        const raw = await SecureStore.getItemAsync(STORE_KEY);
        if (!raw) return;
        try {
            const data = JSON.parse(raw);
            set({ apps: data.apps ?? [] });
        } catch {
            // Corrupted data — start fresh
        }
    }
}));

function persist(state: TrustedAppsState) {
    SecureStore.setItemAsync(STORE_KEY, JSON.stringify({ apps: state.apps })).catch(console.error);
}
