// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import * as SecureStore from '@/utils/storage';
import { create } from 'zustand';

/** A previously verified and trusted enclave app. */
export interface TrustedApp {
    rpId: string;
    origin: string;
    /**
     * Most-recent human-readable app name surfaced through this rpId.
     * Federated sign-ins (multiple websites sharing a single rpId such
     * as `privasys.id`) overwrite this on every successful ceremony so
     * the Home tab labels match the app the user just signed into.
     */
    appName?: string;
    /** Expected MRENCLAVE (SGX) or empty (TDX). */
    mrenclave?: string;
    /** Expected MRTD (TDX) or empty (SGX). */
    mrtd?: string;
    /**
     * Expected TDX runtime measurement registers 1 and 2 from the last
     * verification. With MRTD these form the platform-runtime fingerprint the
     * session-relay enc_pub is pinned to (management-service hashes
     * MRTD|RTMR1|RTMR2), so tracking them lets the wallet notice a platform
     * upgrade that rotates a sealed session even when MRTD is unchanged.
     * Absent on SGX and on records written before RTMR tracking existed.
     */
    rtmr1?: string;
    rtmr2?: string;
    /** Code hash from the last verification. */
    codeHash?: string;
    /** Config Merkle root from the last verification. */
    configRoot?: string;
    /** TEE type: 'sgx' | 'tdx' | 'sev-snp' | 'nvidia-gpu' | 'none' (standard server, no enclave). */
    teeType: 'sgx' | 'tdx' | 'sev-snp' | 'nvidia-gpu' | 'none';
    /** Epoch seconds of last successful attestation verification. */
    lastVerified: number;
    /** Credential ID registered with this app. */
    credentialId: string;
}

export interface TrustedAppsState {
    apps: TrustedApp[];

    addOrUpdate: (app: TrustedApp) => void;
    remove: (rpId: string) => void;
    /** Forget every app. Part of the wallet wipe — see services/wipe.ts. */
    clearAll: () => void;
    getApp: (rpId: string) => TrustedApp | undefined;
    /** Check if an app's attestation matches what we last verified. */
    isAttestationMatch: (
        rpId: string,
        measurements: {
            mrenclave?: string;
            mrtd?: string;
            rtmr1?: string;
            rtmr2?: string;
            codeHash?: string;
            configRoot?: string;
        }
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

    clearAll: () => {
        set({ apps: [] });
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
        // TDX. RTMR1/RTMR2 are part of the platform-runtime measurement the
        // session-relay enc_pub is pinned to, so a change there (e.g. a
        // kernel/initrd bump that leaves MRTD untouched) is a genuine platform
        // upgrade the user should re-approve — matching the enc_pub rotation
        // exactly. Legacy records predating RTMR tracking have them undefined;
        // treat "not previously recorded" as "don't block the match" so we
        // never force a re-approval merely for starting to track them (the
        // next successful ceremony persists them and full comparison resumes).
        // Doubly-lenient on RTMRs: compare only when BOTH the stored record
        // and the fresh measurement carry the value. A TDX cert from a current
        // client always yields RTMR1/RTMR2, so real enclaves are fully
        // compared; the leniency only spares legacy trust rows and any
        // caller that has not started passing RTMRs — neither of which should
        // be misread as a platform change.
        return (
            app.mrtd === measurements.mrtd &&
            (app.rtmr1 == null || measurements.rtmr1 == null || app.rtmr1 === measurements.rtmr1) &&
            (app.rtmr2 == null || measurements.rtmr2 == null || app.rtmr2 === measurements.rtmr2) &&
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
