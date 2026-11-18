// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Fill every store the screens read with the demo holder, in place of the
 * hydrate from secure storage that a real launch runs.
 *
 * Written with `setState`, never through the stores' actions, because the
 * actions persist: a seed should leave nothing behind in storage, so each
 * launch of the demo starts from the same wallet.
 */

import { useAppMessagesStore } from '@/stores/app-messages';
import { useAuthStore } from '@/stores/auth';
import { useCapabilitiesStore } from '@/stores/capabilities';
import { useConsentStore } from '@/stores/consent';
import { useDriveNotificationsStore } from '@/stores/drive-notifications';
import { useProfileStore } from '@/stores/profile';
import { useServiceSessionsStore } from '@/stores/service-sessions';
import { useSessionsStore } from '@/stores/sessions';
import { useSettingsStore } from '@/stores/settings';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

import {
    capabilityRecords,
    consentRecords,
    credentials,
    DEMO_APPS,
    DRIVE,
    holderProfile,
    standingConsents,
    traces,
    trustedAppFor,
    waitingMessages,
} from './fixtures';
import { isDemo } from './gate';

export const DEMO_RELAY_SESSION = 'demo-relay-drive';

/**
 * Seed the demo wallet. `locale` is the device's, so the wallet speaks the
 * language the simulator is set to, as a freshly set-up wallet would.
 */
export function seedDemo(nowMs: number = Date.now(), locale = 'en-GB'): void {
    if (!isDemo()) throw new Error('seedDemo is only for the demo build');
    const now = Math.floor(nowMs / 1000);
    const creds = credentials(now);

    useProfileStore.setState({ profile: { ...holderProfile(now), locale: locale || 'en-GB' } });
    useAuthStore.setState({
        isOnboarded: true,
        credentials: creds,
        isUnlocked: false,
        unlockExpiresAt: 0,
        // No privasys.id session: everything that would use one stays quiet.
        privasysId: null,
        recoveryPhraseSaved: true,
        activeCredentialId: null,
    });
    useTrustedAppsStore.setState({ apps: DEMO_APPS.map((a) => trustedAppFor(a, now)) });
    useServiceSessionsStore.setState({
        traces: traces(now).map((t) => (t.serviceKey === DRIVE.slug ? { ...t, sessionId: DEMO_RELAY_SESSION } : t)),
    });
    // One live sealed session, so Access shows an app in use right now.
    useSessionsStore.setState({
        sessions: [
            {
                sessionId: DEMO_RELAY_SESSION,
                rpId: DRIVE.host,
                origin: DRIVE.host,
                appName: DRIVE.name,
                startedAt: nowMs - 12 * 60_000,
                expiresAt: nowMs + 50 * 60_000,
            },
        ],
    });
    useConsentStore.setState({ records: consentRecords(now), standingConsents: standingConsents(now), receipts: [] });
    useCapabilitiesStore.setState({ records: capabilityRecords(now), hydrated: true });
    useAppMessagesStore.setState({ messages: waitingMessages(now) });
    useDriveNotificationsStore.setState({ hydrated: true });
    // The explainer cards are for a first real connection, not a tour.
    useSettingsStore.setState({ seenFirstConnect: true });
}
