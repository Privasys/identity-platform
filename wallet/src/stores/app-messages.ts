// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * App messages still waiting on the holder: a request or an invitation an
 * attested app sent. The IdP keeps each for a few days, sealed to the holder's
 * key, so one whose push was swiped away or never came is still on Access.
 *
 * Opening one follows its link, which only ever points at the host the
 * platform verified for the app (services/app-message), and tells the IdP to
 * forget it. Not persisted: it is refilled from the IdP each time.
 */

import { create } from 'zustand';

import { appMessageLink, readAppMessage, APP_MESSAGE_TYPE, type AppMessageContent } from '@/services/app-message';
import { openSealedNotification } from '@/services/notify-seal';
import { getCachedPlatformToken } from '@/services/platform-token';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

export interface WaitingAppMessage extends AppMessageContent {
    id: string;
    appId?: string;
    appName?: string;
    appHost?: string;
    /** Where opening it goes, or undefined when it carries no usable link. */
    link?: string;
    createdAt: number;
}

interface ListedMessage {
    id?: unknown;
    kind?: unknown;
    app_id?: unknown;
    app_name?: unknown;
    app_host?: unknown;
    sealed?: unknown;
    created_at?: unknown;
    expires_at?: unknown;
}

/** Turn the IdP's list into what Access shows. Malformed and expired rows are
 *  dropped; a payload this phone cannot open still lists the app and kind. */
export async function readListed(body: unknown, nowSeconds: number): Promise<WaitingAppMessage[]> {
    const rows = (body as { messages?: unknown })?.messages;
    if (!Array.isArray(rows)) return [];
    const out: WaitingAppMessage[] = [];
    for (const r of rows as ListedMessage[]) {
        if (typeof r?.id !== 'string' || !r.id || typeof r.expires_at !== 'number' || r.expires_at <= nowSeconds) {
            continue;
        }
        const kindHint = typeof r.kind === 'string' ? r.kind : undefined;
        const payload =
            typeof r.sealed === 'string' && r.sealed ? await openSealedNotification(r.sealed, APP_MESSAGE_TYPE) : null;
        const content = readAppMessage(payload, kindHint);
        const appHost = typeof r.app_host === 'string' ? r.app_host : undefined;
        out.push({
            ...content,
            id: r.id,
            appId: typeof r.app_id === 'string' ? r.app_id : undefined,
            appName: typeof r.app_name === 'string' ? r.app_name : undefined,
            appHost,
            link: appMessageLink(appHost, content.path),
            createdAt: typeof r.created_at === 'number' ? r.created_at : 0,
        });
    }
    return out;
}

interface AppMessagesState {
    messages: WaitingAppMessage[];
    /** Ask the IdP what is waiting. Silent and never prompts. */
    refresh: () => Promise<void>;
    /** The holder opened or dismissed it: drop it here and at the IdP. */
    dismiss: (id: string) => Promise<void>;
    /** Follow its link, if any, then dismiss it. */
    open: (message: WaitingAppMessage) => Promise<void>;
    clearAll: () => void;
}

let inflight: Promise<void> | null = null;

export async function dismissAppMessage(id: string): Promise<void> {
    try {
        const token = await getCachedPlatformToken();
        if (!token) return;
        await fetch(`${IDP_BASE}/wallet/app-messages/${encodeURIComponent(id)}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${token}` },
        });
    } catch {
        // It expires at the IdP within days anyway.
    }
}

export const useAppMessagesStore = create<AppMessagesState>((set, get) => ({
    messages: [],

    refresh: () => {
        if (inflight) return inflight;
        inflight = (async () => {
            try {
                const token = await getCachedPlatformToken();
                if (!token) return;
                const res = await fetch(`${IDP_BASE}/wallet/app-messages`, {
                    headers: { Authorization: `Bearer ${token}` },
                });
                if (!res.ok) return;
                set({ messages: await readListed(await res.json(), Math.floor(Date.now() / 1000)) });
            } catch (e) {
                console.warn('[APP-MESSAGE] could not list waiting messages', e);
            }
        })().finally(() => {
            inflight = null;
        });
        return inflight;
    },

    dismiss: async (id) => {
        set({ messages: get().messages.filter((m) => m.id !== id) });
        await dismissAppMessage(id);
    },

    open: async (message) => {
        if (message.link) {
            try {
                // Loaded here, not at the top: this store is imported by the
                // wipe, which runs where react-native is not loaded.
                const { Linking } = await import('react-native');
                await Linking.openURL(message.link);
            } catch (e) {
                console.warn('[APP-MESSAGE] could not open the link', e);
                return;
            }
        }
        await get().dismiss(message.id);
    },

    clearAll: () => set({ messages: [] }),
}));
