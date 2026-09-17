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

    /**
     * The holder typed something into the service's setup form when they
     * approved this: a credential for an account of theirs somewhere else.
     *
     * This is what separates the two kinds of grant the holder sees. Without
     * it, a grant over their own Drive and a grant carrying their Gmail
     * password would appear as the same sort of thing, and they are not:
     * revoking the first ends it completely, while revoking the second leaves
     * a credential alive at a provider only the holder can reach.
     */
    setupProvided?: boolean;
    /**
     * The service's own labels for the secret fields ("App password"), so the
     * row can name what was handed over. Labels only. The values made one hop
     * to the service and were never held here.
     */
    secretLabels?: string[];

    /** Epoch seconds when the holder revoked it, if they have. */
    revokedAt?: number;
    /**
     * Epoch seconds when the resource service last confirmed this, and what it
     * said. Absent means the wallet has never managed to ask, so the row is
     * this device's record rather than the truth, and must say so.
     */
    lastCheckedAt?: number;
    checkResult?: 'held' | 'gone';
}

/** How much the wallet actually knows about a row, which the screen must show. */
export type CapabilityState = 'confirmed' | 'unconfirmed' | 'gone' | 'revoked' | 'expired';

/**
 * What to tell the holder about one record.
 *
 * Deliberately never collapses "we asked and it is there" into "we have a note
 * saying we granted it". A list that presents its own cache as fact is the one
 * thing this screen must not do.
 */
export function capabilityState(r: CapabilityRecord, nowSeconds: number): CapabilityState {
    if (r.revokedAt) return 'revoked';
    if (r.checkResult === 'gone') return 'gone';
    if (r.expiresAt && r.expiresAt <= nowSeconds) return 'expired';
    return r.checkResult === 'held' ? 'confirmed' : 'unconfirmed';
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
    /**
     * Mark one as revoked, AFTER the resource service has said so. Never call
     * this on the strength of a tap alone: a row that says "removed" when the
     * service still holds the grant is worse than no screen at all.
     */
    markRevoked: (key: string, atSeconds?: number) => void;
    /** Record what a service answered about one of its capabilities. */
    markChecked: (key: string, result: 'held' | 'gone', atSeconds?: number) => void;
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

    markRevoked: (key, atSeconds) => {
        const at = atSeconds ?? Math.floor(Date.now() / 1000);
        // Kept rather than dropped. "You removed this on 17 September" is an
        // answer; a row that silently disappears is not.
        const records = get().records.map((x) =>
            capabilityKey(x) === key ? { ...x, revokedAt: at, checkResult: 'gone' as const } : x,
        );
        set({ records });
        persist(records);
    },

    markChecked: (key, result, atSeconds) => {
        const at = atSeconds ?? Math.floor(Date.now() / 1000);
        const records = get().records.map((x) =>
            capabilityKey(x) === key ? { ...x, lastCheckedAt: at, checkResult: result } : x,
        );
        set({ records });
        persist(records);
    },

    clearAll: () => {
        set({ records: [] });
        persist([]);
    },
}));
