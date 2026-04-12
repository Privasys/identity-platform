// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Consent store — tracks data sharing decisions and history.
 *
 * Records which apps requested what data, when the user consented/denied,
 * and what attestation state the enclave had at the time.
 */

import * as SecureStore from '@/utils/storage';
import { create } from 'zustand';

/** A single data sharing consent record. */
export interface ConsentRecord {
    /** Unique ID for this consent event. */
    id: string;
    /** RP ID of the requesting enclave app. */
    rpId: string;
    /** Origin of the enclave. */
    origin: string;
    /** Display name of the app (if known). */
    appName?: string;
    /** Attributes that were requested. */
    requestedAttributes: string[];
    /** Attributes the user approved sharing. */
    approvedAttributes: string[];
    /** Attributes the user denied. */
    deniedAttributes: string[];
    /** User decision: 'approved' | 'denied' | 'partial' (some approved, some denied). */
    decision: 'approved' | 'denied' | 'partial';
    /** Whether the user checked "always share with this app". */
    persistent: boolean;
    /** TEE type at the time of consent. */
    teeType: 'sgx' | 'tdx';
    /** MRENCLAVE / MRTD at the time of consent. */
    enclaveMeasurement: string;
    /** Code hash at the time of consent. */
    codeHash: string;
    /** Epoch seconds when consent was given. */
    consentedAt: number;
    /** Epoch seconds when this consent expires (0 = per-request). */
    expiresAt: number;
}

/** Standing consent — "always share X with app Y". */
export interface StandingConsent {
    /** RP ID of the app. */
    rpId: string;
    /** Attributes to auto-share. */
    attributes: string[];
    /** The enclave measurement when standing consent was granted. */
    enclaveMeasurement: string;
    /** Code hash when standing consent was granted. */
    codeHash: string;
    /** Epoch seconds when granted. */
    grantedAt: number;
}

/** Computation receipt from an enclave. */
export interface ComputationReceipt {
    /** Receipt ID. */
    receiptId: string;
    /** RP ID of the enclave app. */
    rpId: string;
    /** Enclave identity (mrenclave or mrtd). */
    enclaveId: string;
    /** Hash of the code that processed the data. */
    codeHash: string;
    /** Hash of the input data. */
    inputHash: string;
    /** Hash of the output/result. */
    outputHash: string;
    /** ISO 8601 timestamp. */
    timestamp: string;
    /** Signature from the enclave's RA-TLS key. */
    signature: string;
    /** Epoch seconds when received. */
    receivedAt: number;
}

export interface ConsentState {
    /** All consent records (history). */
    records: ConsentRecord[];
    /** Standing consents for auto-sharing. */
    standingConsents: StandingConsent[];
    /** Computation receipts. */
    receipts: ComputationReceipt[];

    /** Record a new consent decision. */
    addRecord: (record: ConsentRecord) => void;
    /** Get consent history for a specific app. */
    getRecordsForApp: (rpId: string) => ConsentRecord[];
    /** Set a standing consent. */
    setStandingConsent: (consent: StandingConsent) => void;
    /** Remove a standing consent. */
    removeStandingConsent: (rpId: string) => void;
    /** Get standing consent for an app (if exists and enclave measurement matches). */
    getStandingConsent: (rpId: string, enclaveMeasurement: string, codeHash: string) => StandingConsent | undefined;
    /** Add a computation receipt. */
    addReceipt: (receipt: ComputationReceipt) => void;
    /** Get receipts for a specific app. */
    getReceiptsForApp: (rpId: string) => ComputationReceipt[];
    /** Clear all consent data. */
    clearAll: () => void;
    /** Hydrate from secure storage. */
    hydrate: () => Promise<void>;
}

const STORE_KEY = 'v1-consent';

export const useConsentStore = create<ConsentState>((set, get) => ({
    records: [],
    standingConsents: [],
    receipts: [],

    addRecord: (record) => {
        set((s) => ({ records: [record, ...s.records] }));
        persist(get());
    },

    getRecordsForApp: (rpId) => {
        return get().records.filter((r) => r.rpId === rpId);
    },

    setStandingConsent: (consent) => {
        set((s) => {
            const existing = s.standingConsents.findIndex((c) => c.rpId === consent.rpId);
            if (existing >= 0) {
                const updated = [...s.standingConsents];
                updated[existing] = consent;
                return { standingConsents: updated };
            }
            return { standingConsents: [...s.standingConsents, consent] };
        });
        persist(get());
    },

    removeStandingConsent: (rpId) => {
        set((s) => ({
            standingConsents: s.standingConsents.filter((c) => c.rpId !== rpId)
        }));
        persist(get());
    },

    getStandingConsent: (rpId, enclaveMeasurement, codeHash) => {
        return get().standingConsents.find(
            (c) =>
                c.rpId === rpId &&
                c.enclaveMeasurement === enclaveMeasurement &&
                c.codeHash === codeHash
        );
    },

    addReceipt: (receipt) => {
        set((s) => ({ receipts: [receipt, ...s.receipts] }));
        persist(get());
    },

    getReceiptsForApp: (rpId) => {
        return get().receipts.filter((r) => r.rpId === rpId);
    },

    clearAll: () => {
        set({ records: [], standingConsents: [], receipts: [] });
        SecureStore.deleteItemAsync(STORE_KEY).catch(console.error);
    },

    hydrate: async () => {
        const raw = await SecureStore.getItemAsync(STORE_KEY);
        if (!raw) return;
        try {
            const data = JSON.parse(raw);
            set({
                records: data.records ?? [],
                standingConsents: data.standingConsents ?? [],
                receipts: data.receipts ?? []
            });
        } catch {
            // Corrupted data — start fresh
        }
    }
}));

function persist(state: ConsentState) {
    const data = {
        records: state.records,
        standingConsents: state.standingConsents,
        receipts: state.receipts
    };
    SecureStore.setItemAsync(STORE_KEY, JSON.stringify(data)).catch(console.error);
}
