// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Remove this device from the holder's wallet: take it off the account (each
 * identity, the device list, its passkey and push target), then clear it.
 * Settings and the Devices screen both offer it.
 *
 * Offline, the device cannot sign its way off the account, and once cleared
 * it never could: the holder may clear it anyway, told that it still shows on
 * their other devices until it is removed there.
 *
 * Passkeys this device made for other websites live in its secure chip only
 * and go with it; the confirmation says so before anything happens.
 */

import { useRouter } from 'expo-router';
import { useState } from 'react';
import { Alert } from 'react-native';
import { useTranslation } from 'react-i18next';

import { removeThisPhone } from '@/services/device-flows';
import { localWebsitePasskeyCount } from '@/services/website-passkeys';
import { wipeWallet } from '@/services/wipe';

/** privasys.id could not be reached: the wallet's own network error, or fetch's. */
function isOffline(e: any): boolean {
    return e?.reason === 'network' || /network request failed|could not be reached|offline|internet/i.test(String(e?.message ?? ''));
}

export function useRemoveThisDevice(): { confirm: () => void; busy: boolean } {
    const { t } = useTranslation();
    const router = useRouter();
    const [busy, setBusy] = useState(false);

    const clear = async () => {
        await wipeWallet();
        router.replace('/(tabs)');
    };

    const remove = async () => {
        setBusy(true);
        try {
            try {
                await removeThisPhone();
            } catch (e: any) {
                if (!isOffline(e)) throw e;
                setBusy(false);
                Alert.alert(t('devices.removeOfflineTitle'), t('devices.removeOfflineBody'), [
                    { text: t('common.cancel'), style: 'cancel' },
                    {
                        text: t('devices.removeOfflineConfirm'),
                        style: 'destructive',
                        onPress: () => {
                            setBusy(true);
                            void clear().finally(() => setBusy(false));
                        },
                    },
                ]);
                return;
            }
            await clear();
        } catch (e: any) {
            Alert.alert(t('devices.revokeFailed', { reason: e?.message ?? String(e) }));
        } finally {
            setBusy(false);
        }
    };

    // The website passkeys kept on this device only are lost with it: said with
    // their number, and only when there are any. Backed-up ones live on.
    const confirm = () =>
        void localWebsitePasskeyCount().then((n) =>
            Alert.alert(
                t('devices.removeThisTitle'),
                n > 0
                    ? `${t('devices.removeThisBody')}\n\n${t('devices.removeThisPasskeysCount', { count: n })}`
                    : t('devices.removeThisBody'),
                [
                    { text: t('common.cancel'), style: 'cancel' },
                    { text: t('devices.removeThisConfirm'), style: 'destructive', onPress: () => void remove() },
                ],
            ),
        );

    return { confirm, busy };
}
