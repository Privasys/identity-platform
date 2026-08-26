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
 * Hardware keys go too, and this is the ONLY place that deletes them.
 *
 * They used to survive, on the reasoning that the next identity could re-use
 * them. Two things were wrong with that. A biometric-gated key dies when the
 * phone's fingerprint or face enrolment changes, and since nothing replaced it,
 * every identity created afterwards inherited a key that could not sign: on one
 * tester's iPhone that made the identity verifier permanently unreachable. And
 * the device key's public half travels in the WIA's `cnf.jwk`, which the IdP
 * sees at every enrolment, so two identities created on one phone shared an
 * identifier at exactly the layer designed to be subject-less (2026-08-27).
 *
 * Deleting them here, and only here, means a wipe yields a genuinely new
 * profile, and no failure anywhere else can decide on the user's behalf that
 * their signing key should be destroyed.
 *
 * What deliberately survives:
 *
 *   - The app-language override (see `useSettingsStore.clearAll`).
 *   - The device UUID. It names the hardware, not the person, and the push
 *     token it accompanies is device-scoped and unaffected by a wipe.
 *   - The attribute value-set cache, which holds no personal data.
 */

import { deleteDeviceKey } from '@/services/did';
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

import * as NativeKeys from '../../modules/native-keys/src/index';

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
    // Read before anything is cleared: each credential names the hardware key
    // it registered, and once the store is empty those aliases are unrecoverable
    // and their keys would sit in the keychain for ever.
    const credentialKeyAliases = useAuthStore
        .getState()
        .credentials.map((c) => c.keyAlias)
        .filter(Boolean);

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
        // The device signing key: root of the device DID and of every holder
        // proof. First-run setup mints a fresh one, so the next identity starts
        // with a key this device has never used before.
        settle('device key', deleteDeviceKey()),
        ...credentialKeyAliases.map((alias) =>
            settle(`credential key ${alias}`, NativeKeys.deleteKey(alias)),
        ),
    ]);
}

async function settle(what: string, p: Promise<unknown>): Promise<void> {
    try {
        await p;
    } catch (e) {
        console.warn(`[wipe] could not clear ${what}:`, e instanceof Error ? e.message : e);
    }
}
