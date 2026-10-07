// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Recovery requests waiting on this holder as somebody's guardian.
 *
 * The IdP pushes a guardian when a person they protect starts a recovery. The
 * wallet did nothing with that push: a tap opened it wherever it was, and the
 * request sat at the bottom of Profile, Account Recovery, for a guardian who
 * had to know to look there. This store is what lets Access say a request is
 * waiting, the way it does for vault approvals and access requests.
 *
 * It learns of one two ways. A push says one exists, without saying whose
 * (the push carries nothing else, deliberately). And the IdP lists them, for
 * the guardian's own canonical session, when that session is still live; the
 * list is read silently and never prompts, so with no live session the push
 * is all there is, and the Recovery screen asks the guardian to unlock.
 *
 * Not persisted: a recovery request is answered or abandoned within the
 * session it arrived in, and the IdP is the record.
 */

import { create } from 'zustand';

import { listRecoveryRequests, type RecoveryRequestInfo } from '@/services/recovery-api';
import { useAuthStore } from '@/stores/auth';

interface GuardianRequestsState {
    /** Requests the IdP listed, when it could be asked. */
    requests: RecoveryRequestInfo[];
    /** A push said one is waiting, whether or not it could be listed yet. */
    heard: boolean;
    /** A recovery-request push arrived or was tapped. */
    remember: () => void;
    /** Ask the IdP, silently, with the canonical session if it is still live. */
    refresh: () => Promise<void>;
    clearAll: () => void;
}

/** How many to show as waiting: what was listed, or one when only heard of. */
export function waitingCount(s: Pick<GuardianRequestsState, 'requests' | 'heard'>): number {
    return Math.max(s.requests.length, s.heard ? 1 : 0);
}

let inflight: Promise<void> | null = null;

export const useGuardianRequestsStore = create<GuardianRequestsState>((set) => ({
    requests: [],
    heard: false,

    remember: () => set({ heard: true }),

    refresh: () => {
        if (inflight) return inflight;
        // Cleared by a .finally on the outside, not a finally inside. With no
        // live session the body returns before its first await, so an inner
        // finally ran BEFORE the assignment below and left `inflight` holding
        // a settled promise: every later refresh returned it and did nothing.
        inflight = (async () => {
            try {
                const account = useAuthStore.getState().privasysId;
                const live =
                    !!account?.sessionToken && Date.now() < (account?.sessionExpiresAt ?? 0);
                if (!live) return;
                const res = await listRecoveryRequests(`wallet:${account!.sessionToken}`);
                // The list is the truth once it can be read: an empty one means
                // whatever the push announced has been answered or withdrawn.
                set({ requests: res.requests ?? [], heard: false });
            } catch {
                // Unreachable or no longer signed in: keep what the push said.
            }
        })().finally(() => {
            inflight = null;
        });
        return inflight;
    },

    clearAll: () => set({ requests: [], heard: false }),
}));
