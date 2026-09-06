// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import * as SecureStore from '@/utils/storage';
import { create } from 'zustand';

import type { CapabilityKind, Permission } from '@/services/capabilities';

/**
 * What the holder has granted, and to whom.
 *
 * Enforcement lives at the resource service, next to the data, and revocation
 * belongs there too. This store is ADVISORY: it exists because "what did I
 * approve" is the holder's mental model, and without it the only record of a
 * decision made on this device would be somewhere else entirely.
 *
 * Modelled on stores/dependency-approvals, which is already a capability cache
 * in everything but name: keyed decisions, provenance, and a remembered denial
 * so a re-prompt can say the holder declined before.
 *
 * Keyed by (appId, resourceAppId, kind, resourceLabel). The same app may hold
 * several capabilities over different resources, and they are separate grants
 * that expire and are revoked separately.
 */
export interface CapabilityRecord {
    /** The requesting app's verified app id (OID 4.1). */
    appId: string;
    /** Best-known human name, resolved at approval time. */
    appName?: string;
    /** The resource service's app id. */
    resourceAppId: string;
    resourceAppName?: string;
    kind: CapabilityKind;
    /** The resource as it was described on screen. */
    resourceLabel: string;
    permissions: Permission[];
    decision: 'approved' | 'denied';
    /** The resource service's id for it, when approved. Shown so the holder can
     *  match this record against the list where revocation actually happens. */
    capabilityId?: string;
    /** Epoch seconds. */
    grantedAt: number;
    expiresAt?: number;
}

export function capabilityKey(r: {
    appId: string;
    resourceAppId: string;
    kind: string;
    resourceLabel: string;
}): string {
    return `${r.appId}|${r.resourceAppId}|${r.kind}|${r.resourceLabel}`;
}

interface CapabilitiesState {
    records: CapabilityRecord[];
    hydrated: boolean;
    hydrate: () => Promise<void>;
    record: (r: CapabilityRecord) => void;
    /** The live record for this exact ask, if any. */
    find: (k: {
        appId: string;
        resourceAppId: string;
        kind: string;
        resourceLabel: string;
    }) => CapabilityRecord | undefined;
    /** Forget one record. Does NOT revoke: only the resource service can. */
    forget: (key: string) => void;
    clearAll: () => void;
}

const STORE_KEY = 'v1-capabilities';

function persist(records: CapabilityRecord[]) {
    SecureStore.setItemAsync(STORE_KEY, JSON.stringify({ records })).catch(console.error);
}

export const useCapabilitiesStore = create<CapabilitiesState>((set, get) => ({
    records: [],
    hydrated: false,

    hydrate: async () => {
        if (get().hydrated) return;
        try {
            const raw = await SecureStore.getItemAsync(STORE_KEY);
            const data = raw ? (JSON.parse(raw) as { records?: CapabilityRecord[] }) : null;
            set({ records: data?.records ?? [], hydrated: true });
        } catch {
            set({ records: [], hydrated: true });
        }
    },

    record: (r) => {
        const key = capabilityKey(r);
        // One record per ask. A re-approval REPLACES rather than accumulates:
        // the previous capability has been superseded, and two rows for one
        // thing would make the list lie about how much access was given.
        const records = [...get().records.filter((x) => capabilityKey(x) !== key), r];
        set({ records });
        persist(records);
    },

    find: (k) => get().records.find((x) => capabilityKey(x) === capabilityKey(k)),

    forget: (key) => {
        const records = get().records.filter((x) => capabilityKey(x) !== key);
        set({ records });
        persist(records);
    },

    clearAll: () => {
        set({ records: [] });
        persist([]);
    },
}));
