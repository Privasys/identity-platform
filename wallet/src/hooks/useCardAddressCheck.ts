// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * An address confirmed by the holder's bank with a £0 card check
 * (services/card-check), as Personal Data and Import Data both offer it.
 * Explained first: a card check is unusual enough to say what happens, what is
 * charged (nothing) and what is kept (no card details).
 */

import { useState } from 'react';
import { Alert } from 'react-native';
import { useTranslation } from 'react-i18next';

import { CardCheckError, checkAddressWithCard } from '@/services/card-check';
import { notify, useNoticeStore } from '@/stores/notice';
import { useProfileStore } from '@/stores/profile';

export function useCardAddressCheck(): { start: () => void; busy: boolean } {
    const { t } = useTranslation();
    const [busy, setBusy] = useState(false);

    const run = async () => {
        setBusy(true);
        try {
            await checkAddressWithCard();
            const value = useProfileStore.getState().profile?.attributes.find((a) => a.key === 'address')?.value ?? '';
            useNoticeStore.getState().markFresh([{ key: 'address', value }]);
            notify(t('cardCheck.doneTitle'), t('cardCheck.doneBody'));
        } catch (e: any) {
            if (e instanceof CardCheckError && e.reason === 'cancelled') return;
            if (e instanceof CardCheckError && e.reason === 'nothing-confirmed') {
                Alert.alert(t('cardCheck.nothingConfirmed'));
            } else {
                Alert.alert(t('cardCheck.failed', { reason: e?.message ?? String(e) }));
            }
        } finally {
            setBusy(false);
        }
    };

    const start = () =>
        Alert.alert(t('cardCheck.explainTitle'), t('cardCheck.explainBody'), [
            { text: t('common.cancel'), style: 'cancel' },
            { text: t('common.continue'), onPress: () => void run() },
        ]);

    return { start, busy };
}
