// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * "Clear All Data" — the single place that erases this device's wallet.
 *
 * The screen's own promise is the specification: it removes the profile,
 * credentials, trusted apps "and everything else stored on this device". That
 * had drifted into a hand-written list inside the Profile screen's Alert
 * handler, and the list was incomplete: live relay sessions, session traces,
 * consent history, dependency approvals, Drive share requests, the
 * first-connect flag, the recovery-phrase acknowledgement, the KYC records, the
 * Wallet Instance Attestation, the platform token and the notification-sealing
 * key all survived a wipe. A cleared wallet therefore came back believing its
 * recovery phrase was already saved and still holding passport-derived
 * credentials belonging to the previous identity (reported 2026-08-26).
 *
 * Every persisted store now exposes `clearAll()`, every service that owns a
 * SecureStore key exposes a clear, and this function calls all of them. The
 * test in `__tests__/wipe.test.ts` fails when a new persisted key appears
 * without a corresponding clear, so the list cannot silently rot again.
 *
 * What deliberately survives:
 *
 *   - Hardware keys. They are keyed by alias, never leave secure hardware, and
 *     the next identity on this device re-uses them; deleting them would strand
 *     a user whose biometric enrolment is the only unlock they have.
 *   - The app-language override (see `useSettingsStore.clearAll`).
 *   - The device UUID. It names the hardware, not the person, and the push
 *     token it accompanies is device-scoped and unaffected by a wipe.
 *   - The attribute value-set cache, which holds no personal data.
 */

import { clearKycRecords } from '@/services/kyc';
import { clearNotifySealKey } from '@/services/notify-seal';
import { clearPlatformToken } from '@/services/platform-token';
import { RECOVERY_STATE_KEY } from '@/services/recovery-api';
import { clearSovereignLocalState } from '@/services/sovereign';
import { clearWia } from '@/services/wia';
import { useAuthStore } from '@/stores/auth';
import { useConsentStore } from '@/stores/consent';
import { useDependencyApprovalsStore } from '@/stores/dependency-approvals';
import { useDriveNotificationsStore } from '@/stores/drive-notifications';
import { useProfileStore } from '@/stores/profile';
import { useServiceSessionsStore } from '@/stores/service-sessions';
import { useSessionsStore } from '@/stores/sessions';
import { useSettingsStore } from '@/stores/settings';
import { useTrustedAppsStore } from '@/stores/trusted-apps';
import { useVaultApprovalsStore } from '@/stores/vaultApprovals';
import * as SecureStore from '@/utils/storage';

/**
 * Erase every trace of the current identity from this device.
 *
 * Awaitable, and the caller MUST await it before offering to set a wallet up
 * again: the sovereign root and the stashed recovered seed are deleted
 * asynchronously, and a setup that raced the deletion could pick the previous
 * identity's pairwise seed back up and silently resurrect it.
 *
 * Individually best-effort. One failing SecureStore delete must not abandon the
 * wipe half-done, so failures are logged and the rest still runs.
 */
export async function wipeWallet(): Promise<void> {
    // In-memory stores first: they are synchronous, so the UI drops to its
    // empty state immediately rather than after the storage round-trips.
    useAuthStore.getState().clearAll();
    useProfileStore.getState().clearProfile();
    useTrustedAppsStore.getState().clearAll();
    useSessionsStore.getState().clearAll();
    useServiceSessionsStore.getState().clearAll();
    useConsentStore.getState().clearAll();
    useDependencyApprovalsStore.getState().clearAll();
    useDriveNotificationsStore.getState().clearAll();
    useVaultApprovalsStore.getState().clearAll();
    useSettingsStore.getState().clearAll();

    await Promise.all([
        settle('sovereign state', clearSovereignLocalState()),
        settle('KYC records', clearKycRecords()),
        settle('wallet instance attestation', clearWia()),
        settle('platform token', clearPlatformToken()),
        settle('notification sealing key', clearNotifySealKey()),
        settle('recovery state', SecureStore.deleteItemAsync(RECOVERY_STATE_KEY)),
    ]);
}

async function settle(what: string, p: Promise<unknown>): Promise<void> {
    try {
        await p;
    } catch (e) {
        console.warn(`[wipe] could not clear ${what}:`, e instanceof Error ? e.message : e);
    }
}
