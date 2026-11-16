// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A short message at the top of the screen saying what just happened ("Sent
 * to Drive"), in place of a page that only says it worked. A screen that has
 * finished calls `notify` and goes back; the message (components/Notice) sits
 * above whatever screen the holder lands on, for a few seconds.
 *
 * One message at a time: a newer one replaces the one showing.
 */

import { create } from 'zustand';

export interface Notice {
    /** Bumped on every notify, so the same words shown twice still restart. */
    id: number;
    title: string;
    body?: string;
}

/**
 * What a finished screen just added, for the screen it lands on to pick out:
 * an attribute key, and its value when the key can hold several (emails).
 */
export interface Fresh {
    key: string;
    value?: string;
}

interface NoticeState {
    notice: Notice | null;
    fresh: Fresh[];
    notify: (title: string, body?: string) => void;
    clear: (id?: number) => void;
    /** Mark items as just added, for a few seconds. */
    markFresh: (items: Fresh[]) => void;
}

let next = 1;
let freshTimer: ReturnType<typeof setTimeout> | undefined;
const FRESH_MS = 4000;

export const useNoticeStore = create<NoticeState>((set, get) => ({
    notice: null,
    fresh: [],
    notify: (title, body) => set({ notice: { id: next++, title, body } }),
    // With an id, clears only that message, so a timer cannot remove a newer one.
    clear: (id) => {
        if (id === undefined || get().notice?.id === id) set({ notice: null });
    },
    markFresh: (items) => {
        if (freshTimer) clearTimeout(freshTimer);
        set({ fresh: items });
        freshTimer = setTimeout(() => set({ fresh: [] }), FRESH_MS);
    },
}));

/** Whether an attribute is one a finished screen just added. */
export function isFresh(fresh: Fresh[], key: string, value: string): boolean {
    return fresh.some((f) => f.key === key && (f.value === undefined || f.value === value));
}

/** Show a message, from outside a component. */
export function notify(title: string, body?: string): void {
    useNoticeStore.getState().notify(title, body);
}
