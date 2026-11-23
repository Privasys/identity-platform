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

import { APP_FORM_TYPE, readFormPayload, type AppForm } from '@/services/app-form';
import { APPROVAL_TYPE, readApprovalPayload, type Approval } from '@/services/approval';
import { appMessageLink, readAppMessage, APP_MESSAGE_TYPE, type AppMessageContent } from '@/services/app-message';
import { isDemo } from '@/services/demo/gate';
import { openSealedNotification } from '@/services/notify-seal';
import { oneLoadAtATime } from '@/services/idp-list';
import { callWithPlatformToken, hasPlatformIdentity } from '@/services/platform-token';

const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

export interface WaitingAppMessage extends AppMessageContent {
    id: string;
    /** 'app-message', 'app-form' for a question answered in the wallet, or
     *  'approval' for an act the holder approves. */
    type: string;
    appId?: string;
    appName?: string;
    appHost?: string;
    /** For a form: the app's short name and its platform hostname (built
     *  from that name), where the form is confirmed and answered. */
    appSlug?: string;
    platformHost?: string;
    /** Where opening it goes, or undefined when it carries no usable link. */
    link?: string;
    /** For an app-form: the form, only when it parsed and its digest is the
     *  one the IdP recorded. A form this phone cannot show has none. */
    form?: AppForm;
    /** For an approval: the approval, only when it parsed and its digest is
     *  the one the IdP recorded. */
    approval?: Approval;
    createdAt: number;
    /** When it stops waiting (seconds); an approval waits minutes. */
    expiresAt?: number;
}

export interface ListedMessage {
    id?: unknown;
    type?: unknown;
    kind?: unknown;
    app_id?: unknown;
    app_name?: unknown;
    app_host?: unknown;
    app_slug?: unknown;
    app_platform_host?: unknown;
    form_digest?: unknown;
    sealed?: unknown;
    created_at?: unknown;
    expires_at?: unknown;
}

/** One listed or pushed message, as the wallet shows it. */
export async function readMessage(r: ListedMessage): Promise<WaitingAppMessage | null> {
    if (typeof r?.id !== 'string' || !r.id) return null;
    const type = r.type === APP_FORM_TYPE ? APP_FORM_TYPE : r.type === APPROVAL_TYPE ? APPROVAL_TYPE : APP_MESSAGE_TYPE;
    const kindHint = typeof r.kind === 'string' ? r.kind : undefined;
    // Sealed with the type as associated data, so a message cannot be
    // replayed as a form or the other way round.
    const payload = typeof r.sealed === 'string' && r.sealed ? await openSealedNotification(r.sealed, type) : null;
    const appHost = typeof r.app_host === 'string' ? r.app_host : undefined;
    const base = {
        id: r.id,
        type,
        appId: typeof r.app_id === 'string' ? r.app_id : undefined,
        appName: typeof r.app_name === 'string' ? r.app_name : undefined,
        appHost,
        appSlug: typeof r.app_slug === 'string' ? r.app_slug : undefined,
        platformHost: typeof r.app_platform_host === 'string' ? r.app_platform_host : undefined,
        createdAt: typeof r.created_at === 'number' ? r.created_at : 0,
        expiresAt: typeof r.expires_at === 'number' ? r.expires_at : undefined,
    };
    if (type === APPROVAL_TYPE) {
        const parsed = readApprovalPayload(payload);
        // As for a form: shown only when it is what the IdP will bind.
        const approval = parsed && (r.form_digest === undefined || r.form_digest === parsed.digest) ? parsed : undefined;
        return { ...base, kind: 'request', presented: [], approval };
    }
    if (type === APP_FORM_TYPE) {
        const parsed = readFormPayload(payload);
        // What the holder sees must be what the IdP will bind their answer
        // to: a form whose digest differs from the recorded one is not shown.
        const form = parsed && (r.form_digest === undefined || r.form_digest === parsed.digest) ? parsed : undefined;
        return {
            ...base,
            kind: kindHint === 'invitation' ? 'invitation' : 'request',
            presented: [],
            form,
            link: form ? appMessageLink(appHost, form.link) : undefined,
        };
    }
    const content = readAppMessage(payload, kindHint);
    return { ...base, ...content, link: appMessageLink(appHost, content.path) };
}

/** Turn the IdP's list into what Access shows. Malformed and expired rows are
 *  dropped; a payload this phone cannot open still lists the app and kind. */
export async function readListed(body: unknown, nowSeconds: number): Promise<WaitingAppMessage[]> {
    const rows = (body as { messages?: unknown })?.messages;
    if (!Array.isArray(rows)) return [];
    const out: WaitingAppMessage[] = [];
    for (const r of rows as ListedMessage[]) {
        if (typeof r?.expires_at !== 'number' || r.expires_at <= nowSeconds) continue;
        const m = await readMessage(r);
        if (m) out.push(m);
    }
    return out;
}

interface AppMessagesState {
    messages: WaitingAppMessage[];
    /** The last load could not read the list: what is shown may be missing
     *  something. Never set for a wallet with no privasys.id identity. */
    loadFailed: boolean;
    /** Ask the IdP what is waiting. Never prompts unless `interactive` (the
     *  holder tapped Try again), which may mint a token with Face ID. */
    refresh: (opts?: { interactive?: boolean }) => Promise<void>;
    /** The holder opened or dismissed it: drop it here and at the IdP. */
    dismiss: (id: string) => Promise<void>;
    /** Follow its link, if any, then dismiss it. */
    open: (message: WaitingAppMessage) => Promise<void>;
    /** Add one that arrived by push, so its screen can open before the list
     *  is refreshed. Replaces a listed copy with the same id. */
    remember: (message: WaitingAppMessage) => void;
    /** Drop one from this phone's list only (a form once answered: the IdP
     *  already took it). */
    forget: (id: string) => void;
    clearAll: () => void;
}

/**
 * Ask the IdP what is waiting. A token privasys.id refuses is dropped
 * (platform-token); in the background nothing is minted, so the list says it
 * could not load and the holder's Try again mints one.
 */
const loadList = oneLoadAtATime(async (interactive) => {
    const set = useAppMessagesStore.setState;
    try {
        const called = await callWithPlatformToken(
            (token) => fetch(`${IDP_BASE}/wallet/app-messages`, { headers: { Authorization: `Bearer ${token}` } }),
            { interactive },
        );
        if (!called) {
            set({ loadFailed: hasPlatformIdentity() });
            return;
        }
        const { res } = called;
        if (!res.ok) {
            console.warn(`[APP-MESSAGE] could not list waiting messages (${res.status})`);
            set({ loadFailed: true });
            return;
        }
        set({ messages: await readListed(await res.json(), Math.floor(Date.now() / 1000)), loadFailed: false });
    } catch (e) {
        console.warn('[APP-MESSAGE] could not list waiting messages', e);
        set({ loadFailed: true });
    }
});

export async function dismissAppMessage(id: string): Promise<void> {
    try {
        await callWithPlatformToken(
            (token) =>
                fetch(`${IDP_BASE}/wallet/app-messages/${encodeURIComponent(id)}`, {
                    method: 'DELETE',
                    headers: { Authorization: `Bearer ${token}` },
                }),
            { interactive: false },
        );
    } catch {
        // It expires at the IdP within days anyway.
    }
}

export const useAppMessagesStore = create<AppMessagesState>((set, get) => ({
    messages: [],

    loadFailed: false,

    refresh: (opts) => {
        // The demo's waiting items are seeded; there is no IdP to ask.
        if (isDemo()) return Promise.resolve();
        return loadList(opts);
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

    remember: (message) => set({ messages: [message, ...get().messages.filter((m) => m.id !== message.id)] }),

    forget: (id) => set({ messages: get().messages.filter((m) => m.id !== id) }),

    clearAll: () => set({ messages: [], loadFailed: false }),
}));
