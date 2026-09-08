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
 * persisted op would almost always be dead. `refresh()` fetches each known op
 * and prunes the ones the IdP has dropped (approved or expired), so `pending`
 * is always the live set — which the Home banner and the approvals screen both
 * render reactively.
 */

import { create } from 'zustand';

import {
    fetchVaultApproval,
    listVaultApprovals,
    type VaultApprovalRequest,
} from '@/services/vault-approval-api';
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
    /** Re-fetch every known op; prune the dead; update `pending`. */
    refresh: () => Promise<void>;
    /**
     * Ask the IdP for everything pending for this wallet's privasys.id identity,
     * then refresh. This is what makes an approval findable when its push never
     * arrived; `refresh()` alone can only ever re-check ops we already saw.
     */
    discover: () => Promise<void>;
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

    clearAll: () => {
        set({ knownOps: [], pending: [], loading: false });
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

    discover: async () => {
        const account = getPrivasysAccount();
        // A stored-but-expired session just 401s; the next sign-in refreshes it.
        if (!account?.sessionToken) return;
        if (!account.sessionExpiresAt || Date.now() >= account.sessionExpiresAt) return;
        try {
            const live = await listVaultApprovals(account.sessionToken);
            if (live.length > 0) {
                set((s) => ({
                    knownOps: Array.from(
                        new Set([...s.knownOps, ...live.map((r) => r.vault_op)]),
                    ),
                }));
            }
        } catch (e) {
            // Discovery is an enhancement over the push path: if it fails we
            // still show whatever the pushes told us about.
            console.warn('[vault-approvals] discover failed', e);
        }
        await get().refresh();
    },
}));
