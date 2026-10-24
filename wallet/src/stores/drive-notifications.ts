// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Drive notifications + the attribute referential.
 *
 * The drive keeps a requester's presented attributes only while their
 * request waits (7 days at most); the WALLET is where names live. Every
 * share-request notification carries them in its sealed payload, and the
 * request list fills in any a missed push left out. This store keeps them as
 * an on-device referential (sub -> attributes) so the wallet can
 * decorate any raw sub the drive hands back (requests, shares, metrics).
 * The mapping never leaves the device.
 *
 * Also holds the request inbox (owner side: approve/deny) and the
 * decision inbox (requester side: outcome updates). Persisted in the
 * device secure store.
 */

import { create } from 'zustand';

import * as SecureStore from '@/utils/storage';

/** One known counterparty: the attributes they presented, by sub. */
export interface KnownSubject {
    sub: string;
    attributes: Record<string, string>;
    /** Display name of the app the attributes arrived through. */
    viaApp?: string;
    firstSeen: number; // epoch seconds
    lastSeen: number;
}

/** Owner side: a pending (or decided) access request on something shared. */
export interface ShareRequest {
    requestId: string;
    tenantId: string;
    nodeId: string;
    nodeName: string;
    requesterSub: string;
    scope: string[];
    receivedAt: number;
    /** Local view of the decision; undefined while pending. */
    decision?: 'approved' | 'denied';
}

/** Requester side: an update on a request the user filed. */
export interface ShareDecision {
    requestId: string;
    nodeName: string;
    status: 'approved' | 'denied';
    receivedAt: number;
}

interface DriveNotificationsState {
    subjects: Record<string, KnownSubject>;
    requests: ShareRequest[];
    decisions: ShareDecision[];
    hydrated: boolean;

    /** File a share-request notification (idempotent by requestId). */
    addRequest: (r: Omit<ShareRequest, 'receivedAt'>, attributes: Record<string, string>, viaApp?: string) => void;
    /** File a share-decision notification (idempotent by requestId+status). */
    addDecision: (d: Omit<ShareDecision, 'receivedAt'>) => void;
    /** Record the local approve/deny outcome on a request. */
    markDecided: (requestId: string, decision: 'approved' | 'denied') => void;
    /**
     * Reconcile with the drive's own request list (the source of truth):
     * requests the wallet never saw a sealed payload for are added (sub
     * only — the referential decorates when it can), and requests
     * decided elsewhere (web UI, another device) get their outcome.
     */
    syncServer: (
        tenantId: string,
        rows: {
            id: string;
            node_id: string;
            node_name: string;
            requester_sub: string;
            scope: string[];
            status: 'pending' | 'approved' | 'denied';
            attributes?: Record<string, string>;
        }[]
    ) => void;
    /** Decorate a raw sub from the drive with known attributes. */
    lookup: (sub: string) => KnownSubject | undefined;
    /** Pending (undecided) requests, newest first. */
    pendingRequests: () => ShareRequest[];
    /**
     * Drop every subject, request and decision. Part of the wallet wipe — see
     * services/wipe.ts. `hydrated` stays true: the store IS loaded, it is
     * simply empty, and resetting it would make the Drive tab spin forever.
     */
    clearAll: () => void;
    hydrate: () => Promise<void>;
}

const STORE_KEY = 'v1-drive-notifications';

function persist(state: DriveNotificationsState) {
    const data = {
        subjects: state.subjects,
        requests: state.requests.slice(-200),
        decisions: state.decisions.slice(-200),
    };
    SecureStore.setItemAsync(STORE_KEY, JSON.stringify(data)).catch(console.error);
}

export const useDriveNotificationsStore = create<DriveNotificationsState>((set, get) => ({
    subjects: {},
    requests: [],
    decisions: [],
    hydrated: false,

    addRequest: (r, attributes, viaApp) => {
        const now = Math.floor(Date.now() / 1000);
        set((s) => {
            const existing = s.subjects[r.requesterSub];
            const subjects = {
                ...s.subjects,
                [r.requesterSub]: {
                    sub: r.requesterSub,
                    // Newly presented attributes win key-by-key; older keys survive.
                    attributes: { ...existing?.attributes, ...attributes },
                    viaApp: viaApp ?? existing?.viaApp,
                    firstSeen: existing?.firstSeen ?? now,
                    lastSeen: now,
                },
            };
            const requests = s.requests.some((x) => x.requestId === r.requestId)
                ? s.requests
                : [...s.requests, { ...r, receivedAt: now }];
            return { subjects, requests };
        });
        persist(get());
    },

    addDecision: (d) => {
        const now = Math.floor(Date.now() / 1000);
        set((s) => {
            if (s.decisions.some((x) => x.requestId === d.requestId && x.status === d.status)) {
                return s;
            }
            return { decisions: [...s.decisions, { ...d, receivedAt: now }] };
        });
        persist(get());
    },

    markDecided: (requestId, decision) => {
        set((s) => ({
            requests: s.requests.map((r) => (r.requestId === requestId ? { ...r, decision } : r)),
        }));
        persist(get());
    },

    syncServer: (tenantId, rows) => {
        const now = Math.floor(Date.now() / 1000);
        set((s) => {
            const byId = new Map(s.requests.map((r) => [r.requestId, r]));
            let subjects = s.subjects;
            let changed = false;
            for (const row of rows) {
                // Drive keeps what the requester presented while the request
                // waits. A missed push leaves nothing on the device, so fill the
                // referential from it; what a push brought is never overwritten.
                const presented = row.attributes ?? {};
                if (!row.status || row.status === 'pending') {
                    const known = subjects[row.requester_sub];
                    const missing = Object.entries(presented).filter(([k]) => !(k in (known?.attributes ?? {})));
                    if (missing.length > 0) {
                        subjects = {
                            ...subjects,
                            [row.requester_sub]: {
                                sub: row.requester_sub,
                                attributes: { ...Object.fromEntries(missing), ...known?.attributes },
                                viaApp: known?.viaApp,
                                firstSeen: known?.firstSeen ?? now,
                                lastSeen: now,
                            },
                        };
                        changed = true;
                    }
                }
                const decision =
                    row.status === 'approved' ? ('approved' as const)
                    : row.status === 'denied' ? ('denied' as const)
                    : undefined;
                const existing = byId.get(row.id);
                if (!existing) {
                    byId.set(row.id, {
                        requestId: row.id,
                        tenantId,
                        nodeId: row.node_id,
                        nodeName: row.node_name,
                        requesterSub: row.requester_sub,
                        scope: row.scope?.length ? row.scope : ['read'],
                        receivedAt: now,
                        decision,
                    });
                    changed = true;
                } else if (decision && existing.decision !== decision) {
                    byId.set(row.id, { ...existing, decision });
                    changed = true;
                }
            }
            if (!changed) return s;
            return { requests: [...byId.values()], subjects };
        });
        persist(get());
    },

    clearAll: () => {
        set({ subjects: {}, requests: [], decisions: [] });
        persist(get());
    },

    lookup: (sub) => get().subjects[sub],

    pendingRequests: () =>
        get()
            .requests.filter((r) => !r.decision)
            .sort((a, b) => b.receivedAt - a.receivedAt),

    hydrate: async () => {
        if (get().hydrated) return;
        try {
            const raw = await SecureStore.getItemAsync(STORE_KEY);
            if (raw) {
                const data = JSON.parse(raw) as Partial<DriveNotificationsState>;
                set({
                    subjects: data.subjects ?? {},
                    requests: data.requests ?? [],
                    decisions: data.decisions ?? [],
                });
            }
        } catch (e) {
            console.warn('[drive-notifications] hydrate failed', e);
        }
        set({ hydrated: true });
    },
}));
