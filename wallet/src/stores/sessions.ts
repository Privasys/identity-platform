// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Live session-relay sessions where the wallet is acting as the
 * verifier+relay for a browser/SDK consumer (Phase E of the
 * session-relay plan). Sessions appear on the Home screen while the
 * wallet has a live binding for them, and disappear on expiry.
 *
 * Not persisted: sessions are ephemeral per-app-lifecycle. If the
 * wallet is killed, the relay binding on the enclave side is lost
 * anyway and the browser must re-run the wallet flow.
 */

import { create } from 'zustand';

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
}

export const useSessionsStore = create<SessionsState>((set, get) => ({
    sessions: [],

    add: (session) => {
        set((s) => {
            const others = s.sessions.filter((x) => x.sessionId !== session.sessionId);
            return { sessions: [...others, session] };
        });
    },

    remove: (sessionId) => {
        set((s) => ({ sessions: s.sessions.filter((x) => x.sessionId !== sessionId) }));
    },

    pruneExpired: () => {
        const now = Math.floor(Date.now() / 1000);
        const live = get().sessions.filter((s) => s.expiresAt > now);
        if (live.length !== get().sessions.length) {
            set({ sessions: live });
        }
    }
}));
