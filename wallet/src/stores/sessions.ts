// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Live session-relay sessions where the wallet is acting as the
 * verifier+relay for a browser/SDK consumer (Phase E of the
 * session-relay plan). Sessions appear on the Home screen while the
 * wallet has a live binding for them, and disappear on expiry.
 *
 * Persisted to SecureStore so users can see live sessions across app
 * restarts (the enclave-side binding survives until expiresAt
 * regardless of whether the wallet is running).
 */

import { create } from 'zustand';

import * as SecureStore from '@/utils/storage';

const STORE_KEY = 'privasys.sessions.v1';

export interface RelaySession {
    /** Enclave-issued session id (from /__privasys/session-bootstrap). */
    sessionId: string;
    /** App rpId (e.g. "confidential-ai-demo.apps-test.privasys.org"). */
    rpId: string;
    /** Enclave origin (host:port). */
    origin: string;
    /** Optional human-readable app name. */
    appName?: string;
    /** Epoch seconds when the enclave will discard the binding. */
    expiresAt: number;
    /** Epoch seconds when the wallet registered the session. */
    startedAt: number;
}

interface SessionsState {
    sessions: RelaySession[];
    add: (session: RelaySession) => void;
    remove: (sessionId: string) => void;
    /** Drop expired sessions. Call from a timer in the UI. */
    pruneExpired: () => void;
    /** Hydrate from secure storage. */
    hydrate: () => Promise<void>;
}

export const useSessionsStore = create<SessionsState>((set, get) => ({
    sessions: [],

    add: (session) => {
        set((s) => {
            const others = s.sessions.filter((x) => x.sessionId !== session.sessionId);
            return { sessions: [...others, session] };
        });
        persist(get());
    },

    remove: (sessionId) => {
        set((s) => ({ sessions: s.sessions.filter((x) => x.sessionId !== sessionId) }));
        persist(get());
    },

    pruneExpired: () => {
        const now = Math.floor(Date.now() / 1000);
        const live = get().sessions.filter((s) => s.expiresAt > now);
        if (live.length !== get().sessions.length) {
            set({ sessions: live });
            persist(get());
        }
    },

    hydrate: async () => {
        const raw = await SecureStore.getItemAsync(STORE_KEY);
        if (!raw) return;
        try {
            const data = JSON.parse(raw);
            const now = Math.floor(Date.now() / 1000);
            const sessions: RelaySession[] = Array.isArray(data?.sessions)
                ? data.sessions.filter((s: RelaySession) => s && s.expiresAt > now)
                : [];
            set({ sessions });
        } catch {
            // Corrupted data — start fresh.
        }
    }
}));

function persist(state: SessionsState) {
    SecureStore.setItemAsync(STORE_KEY, JSON.stringify({ sessions: state.sessions })).catch(
        console.error
    );
}
