// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Drive notifications + the attribute referential.
 *
 * The drive stores subjects only (its PII boundary); the WALLET is where
 * names live. Every share-request notification carries the requester's
 * presented attributes in its sealed payload — this store keeps them as
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
    /** Decorate a raw sub from the drive with known attributes. */
    lookup: (sub: string) => KnownSubject | undefined;
    /** Pending (undecided) requests, newest first. */
    pendingRequests: () => ShareRequest[];
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
