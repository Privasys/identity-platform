// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import * as SecureStore from '@/utils/storage';
import { create } from 'zustand';

/**
 * How enclaves are verified by default.
 *  - `deterministic` (default): report_data is bound to the certificate's
 *    minute-truncated NotBefore. Cheap — the enclave can serve a stable cert.
 *  - `challenge`: the wallet sends a fresh random nonce in the TLS ClientHello;
 *    the enclave folds it plus the TLS channel binder into a fresh quote,
 *    proving liveness and binding the attestation to this exact session.
 * The attestation service is always consulted regardless of mode.
 */
export type VerificationMode = 'deterministic' | 'challenge';

export interface SettingsState {
    /** Biometric grace period in seconds. 0 = always prompt. */
    gracePeriodSec: number;
    /** Default enclave verification mode. Deterministic unless the user opts in. */
    verificationMode: VerificationMode;

    setGracePeriod: (seconds: number) => void;
    setVerificationMode: (mode: VerificationMode) => void;
    hydrate: () => Promise<void>;
}

const STORE_KEY = 'v1-settings';
const GRACE_OPTIONS = [0, 15, 30, 60];

export { GRACE_OPTIONS };

function persist(get: () => SettingsState) {
    const s = get();
    SecureStore.setItemAsync(
        STORE_KEY,
        JSON.stringify({
            gracePeriodSec: s.gracePeriodSec,
            verificationMode: s.verificationMode,
        })
    ).catch(console.error);
}

export const useSettingsStore = create<SettingsState>((set, get) => ({
    gracePeriodSec: 30,
    verificationMode: 'deterministic',

    setGracePeriod: (seconds) => {
        set({ gracePeriodSec: seconds });
        persist(get);
    },

    setVerificationMode: (mode) => {
        set({ verificationMode: mode });
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
            if (data.verificationMode === 'deterministic' || data.verificationMode === 'challenge') {
                set({ verificationMode: data.verificationMode });
            }
        } catch {
            // Corrupted — use defaults
        }
    }
}));
