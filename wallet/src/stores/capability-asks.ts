// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Access requests an app has sent this holder that are still open.
 *
 * The push used to be the only way the wallet learned of one. Swipe it away,
 * or have it never arrive, and the ask sat unanswerable until it expired and
 * the app had to ask again. The IdP relays every such push, so it also keeps
 * the ask (the nonce and the host, which is all the push carried) for as long
 * as the app keeps it open, and this store lists them.
 *
 * Nothing here is trusted beyond "go and look". Opening one runs the same
 * screen a push opens: attest the host, then read the request inside that
 * channel, where a nonce the app has settled or dropped is refused.
 *
 * Not persisted: an ask lives for minutes. Cleared by the wipe with the rest
 * of the in-memory stores' state, since it is only ever refilled from the IdP.
 */

import { create } from 'zustand';

import { getCachedPlatformToken } from '@/services/platform-token';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

export interface CapabilityAsk {
    nonce: string;
    app_host: string;
    app_id?: string;
    app_name?: string;
    created_at: number;
    expires_at: number;
}

interface CapabilityAsksState {
    asks: CapabilityAsk[];
    /** Ask the IdP what is open. Silent and never prompts: without a cached
     *  platform token it leaves the list as it is. */
    refresh: () => Promise<void>;
    /** The holder decided, or the app no longer has it: drop it here and at
     *  the IdP. Never throws. */
    dismiss: (nonce: string) => Promise<void>;
    clearAll: () => void;
}

/** Live, well-formed asks only; a malformed entry is dropped, not shown. */
export function parseAsks(body: unknown, nowSeconds: number): CapabilityAsk[] {
    const pending = (body as { pending?: unknown })?.pending;
    if (!Array.isArray(pending)) return [];
    return pending.filter(
        (a): a is CapabilityAsk =>
            !!a &&
            typeof a.nonce === 'string' &&
            a.nonce !== '' &&
            typeof a.app_host === 'string' &&
            a.app_host !== '' &&
            typeof a.expires_at === 'number' &&
            a.expires_at > nowSeconds,
    );
}

let inflight: Promise<void> | null = null;

export const useCapabilityAsksStore = create<CapabilityAsksState>((set, get) => ({
    asks: [],

    refresh: () => {
        if (inflight) return inflight;
        inflight = (async () => {
            try {
                const token = await getCachedPlatformToken();
                if (!token) return;
                const res = await fetch(`${IDP_BASE}/capability-requests/pending`, {
                    headers: { Authorization: `Bearer ${token}` },
                });
                if (!res.ok) return;
                set({ asks: parseAsks(await res.json(), Math.floor(Date.now() / 1000)) });
            } catch (e) {
                console.warn('[CAPABILITY] could not list open access requests', e);
            } finally {
                inflight = null;
            }
        })();
        return inflight;
    },

    dismiss: async (nonce) => {
        set({ asks: get().asks.filter((a) => a.nonce !== nonce) });
        try {
            const token = await getCachedPlatformToken();
            if (!token) return;
            await fetch(`${IDP_BASE}/capability-requests/pending/${encodeURIComponent(nonce)}`, {
                method: 'DELETE',
                headers: { Authorization: `Bearer ${token}` },
            });
        } catch {
            // The IdP forgets it within minutes anyway.
        }
    },

    clearAll: () => set({ asks: [] }),
}));
