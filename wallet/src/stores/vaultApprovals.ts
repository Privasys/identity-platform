// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Pending vault approvals the wallet has been made aware of this session.
 *
 * A pending approval is only ever knowable by its capability (`vault_op`, a
 * 256-bit short-TTL single-use value delivered via the owner-authenticated push
 * and its notification). There is deliberately no list-by-identity endpoint —
 * that would require the server-side pairwise mapping the platform refuses to
 * keep. So this store is the union of every `vault_op` this app process has
 * seen: from a foreground/tapped push, from a cold-start launch, and — the case
 * that made approvals "invisible when you just open the wallet" — from sweeping
 * the notification tray on open (see hooks/useExpoPushToken sweepPresentedApprovals).
 *
 * Deliberately NOT persisted: pendings expire server-side in minutes, so a
 * persisted op would almost always be dead. `refresh()` fetches each known op
 * and prunes the ones the IdP has dropped (approved or expired), so `pending`
 * is always the live set — which the Home banner and the approvals screen both
 * render reactively.
 */

import { create } from 'zustand';

import { fetchVaultApproval, type VaultApprovalRequest } from '@/services/vault-approval-api';

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
    /** Re-fetch every known op; prune the dead; update `pending`. */
    refresh: () => Promise<void>;
}

export const useVaultApprovalsStore = create<VaultApprovalsState>((set, get) => ({
    knownOps: [],
    pending: [],
    loading: false,

    remember: (vaultOp) => {
        if (!vaultOp || get().knownOps.includes(vaultOp)) return;
        set((s) => ({ knownOps: [...s.knownOps, vaultOp] }));
        void get().refresh();
    },

    forget: (vaultOp) => {
        set((s) => ({
            knownOps: s.knownOps.filter((o) => o !== vaultOp),
            pending: s.pending.filter((r) => r.vault_op !== vaultOp),
        }));
    },

    refresh: async () => {
        const ops = get().knownOps;
        if (ops.length === 0) {
            set({ pending: [], loading: false });
            return;
        }
        set({ loading: true });
        const found: VaultApprovalRequest[] = [];
        const dead: string[] = [];
        await Promise.all(
            ops.map(async (op) => {
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
            pending: found,
            knownOps: s.knownOps.filter((o) => !dead.includes(o)),
            loading: false,
        }));
    },
}));
