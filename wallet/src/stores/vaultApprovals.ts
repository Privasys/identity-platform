// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Pending vault approvals the wallet has been made aware of this session.
 *
 * A pending approval is identified by its capability (`vault_op`, a 256-bit
 * short-TTL single-use value). The wallet learns of one in two ways:
 *
 *  1. the owner-authenticated push and its notification — convenient, but
 *     best-effort: the subject may have no registered push token, and a dropped
 *     push is indistinguishable from a delivered one;
 *  2. `discover()`, which asks the IdP for everything pending for THIS wallet's
 *     privasys.id session (`/fido2/vault-approval/pending` with the wallet
 *     session bearer).
 *
 * (2) exists because relying on the push alone made a lost notification look
 * like no request at all — the approval stayed invisible until it expired. It
 * resolves a single session's own subject, which the IdP already knows from the
 * push-token registration, so it joins nothing across the wallet's pairwise
 * identities.
 *
 * So this store is the union of every `vault_op` this app process has seen:
 * from a foreground/tapped push, from a cold-start launch, from sweeping the
 * notification tray on open (see hooks/useExpoPushToken sweepPresentedApprovals),
 * and from discovery.
 *
 * Deliberately NOT persisted: pendings expire server-side in minutes, so a
 * persisted op would almost always be dead. `refresh()` keeps what discovery
 * just listed, fetches each other known op and prunes the ones the IdP has
 * dropped (approved or expired), so `pending` is always the live set, which
 * the Home banner and the approvals screen both render reactively.
 */

import { create } from 'zustand';

import {
    declineVaultApproval,
    declineVaultBatch,
    fetchVaultApproval,
    fetchVaultBatch,
    listVaultApprovals,
    type VaultApprovalRequest,
} from '@/services/vault-approval-api';
import { requestAnswered } from '@/services/notification-dismiss';
import { getPrivasysAccount } from '@/services/privasys-id';

interface VaultApprovalsState {
    /** Capabilities seen this session (may include some already dead). */
    knownOps: string[];
    /** Live requests, most-recently-expiring last (sorted for display). */
    pending: VaultApprovalRequest[];
    loading: boolean;
    /** Record a capability and refresh so `pending` reflects it. Idempotent. */
    remember: (vaultOp: string) => void;
    /** Drop a capability (approved or dismissed) from both sets. */
    forget: (vaultOp: string) => void;
    /** Forget every capability. Part of the wallet wipe — see services/wipe.ts. */
    clearAll: () => void;
    /** Fetch every known op not in `listed`; prune the dead; update `pending`. */
    refresh: (listed?: VaultApprovalRequest[]) => Promise<void>;
    /**
     * Ask the IdP for everything pending for this wallet's privasys.id identity,
     * then refresh. This is what makes an approval findable when its push never
     * arrived; `refresh()` alone can only ever re-check ops we already saw.
     */
    discover: () => Promise<void>;
    /** Batches still open on the identity provider. Each card verifies its own
     *  list when it opens; these ids only say that one is waiting. */
    batchIds: string[];
    rememberBatch: (batchId: string) => void;
    forgetBatch: (batchId: string) => void;
    /** Drop the batches the identity provider no longer holds. */
    refreshBatches: () => Promise<void>;
    /** Capabilities and batch ids the holder declined this session. Discovery,
     *  the tray sweep and a late push never bring them back, so a declined
     *  request stays gone even from an identity provider that cannot drop it
     *  and only lets it expire. */
    declined: string[];
    /** Decline one request: hide it, then tell the identity provider. */
    decline: (vaultOp: string) => void;
    /** Decline a batch: hide it, then tell the identity provider. */
    declineBatch: (batchId: string) => void;
}

export const useVaultApprovalsStore = create<VaultApprovalsState>((set, get) => ({
    knownOps: [],
    pending: [],
    loading: false,
    batchIds: [],
    declined: [],

    decline: (vaultOp) => {
        if (!vaultOp) return;
        set((s) => ({
            declined: s.declined.includes(vaultOp) ? s.declined : [...s.declined, vaultOp],
            knownOps: s.knownOps.filter((o) => o !== vaultOp),
            pending: s.pending.filter((r) => r.vault_op !== vaultOp),
        }));
        void declineVaultApproval(vaultOp);
        requestAnswered('vault-approval', vaultOp);
    },

    declineBatch: (batchId) => {
        if (!batchId) return;
        set((s) => ({
            declined: s.declined.includes(batchId) ? s.declined : [...s.declined, batchId],
            batchIds: s.batchIds.filter((b) => b !== batchId),
        }));
        void declineVaultBatch(batchId);
        requestAnswered('vault-approval-batch', batchId);
    },

    rememberBatch: (batchId) => {
        if (!batchId || get().batchIds.includes(batchId) || get().declined.includes(batchId)) return;
        set((s) => ({ batchIds: [...s.batchIds, batchId] }));
        // A notification left in the tray can name a batch that has closed.
        void get().refreshBatches();
    },

    forgetBatch: (batchId) => {
        set((s) => ({ batchIds: s.batchIds.filter((b) => b !== batchId) }));
        // Answered or gone: its notification has nothing left to ask.
        requestAnswered('vault-approval-batch', batchId);
    },

    refreshBatches: async () => {
        const dead: string[] = [];
        await Promise.all(
            get().batchIds.map(async (id) => {
                try {
                    if ((await fetchVaultBatch(id)).kind === 'gone') dead.push(id);
                } catch (e) {
                    console.warn('[vault-approvals] batch fetch failed', e);
                }
            }),
        );
        if (dead.length) set((s) => ({ batchIds: s.batchIds.filter((b) => !dead.includes(b)) }));
    },

    remember: (vaultOp) => {
        if (!vaultOp || get().knownOps.includes(vaultOp) || get().declined.includes(vaultOp)) return;
        set((s) => ({ knownOps: [...s.knownOps, vaultOp] }));
        void get().refresh();
    },

    forget: (vaultOp) => {
        set((s) => ({
            knownOps: s.knownOps.filter((o) => o !== vaultOp),
            pending: s.pending.filter((r) => r.vault_op !== vaultOp),
        }));
        // Approved here: its notification has nothing left to ask, on this
        // phone or on the holder's others.
        requestAnswered('vault-approval', vaultOp);
    },

    clearAll: () => {
        set({ knownOps: [], pending: [], loading: false, batchIds: [], declined: [] });
    },

    refresh: async (listed = []) => {
        void get().refreshBatches();
        const ops = get().knownOps;
        if (ops.length === 0) {
            set({ pending: [], loading: false });
            return;
        }
        set({ loading: true });
        // What discovery listed a moment ago is live: only the rest is fetched.
        const found: VaultApprovalRequest[] = listed.filter((r) => ops.includes(r.vault_op));
        const dead: string[] = [];
        await Promise.all(
            ops.filter((op) => !found.some((r) => r.vault_op === op)).map(async (op) => {
                try {
                    const req = await fetchVaultApproval(op);
                    if (req) found.push(req);
                    else dead.push(op); // approved or expired server-side
                } catch (e) {
                    console.warn('[vault-approvals] fetch failed', e);
                }
            }),
        );
        found.sort((a, b) => b.expires_at - a.expires_at);
        set((s) => ({
            // Less any declined while the fetch was in flight.
            pending: found.filter((r) => !s.declined.includes(r.vault_op)),
            knownOps: s.knownOps.filter((o) => !dead.includes(o)),
            loading: false,
        }));
    },

    discover: async () => {
        const account = getPrivasysAccount();
        // A stored-but-expired session just 401s; the next sign-in refreshes it.
        if (!account?.sessionToken) return;
        if (!account.sessionExpiresAt || Date.now() >= account.sessionExpiresAt) return;
        let live: VaultApprovalRequest[] = [];
        try {
            live = await listVaultApprovals(account.sessionToken);
            if (live.length > 0) {
                set((s) => ({
                    knownOps: Array.from(
                        new Set([
                            ...s.knownOps,
                            ...live.map((r) => r.vault_op).filter((o) => !s.declined.includes(o)),
                        ]),
                    ),
                }));
            }
        } catch (e) {
            // Discovery is an enhancement over the push path: if it fails we
            // still show whatever the pushes told us about.
            console.warn('[vault-approvals] discover failed', e);
        }
        await get().refresh(live);
    },
}));
