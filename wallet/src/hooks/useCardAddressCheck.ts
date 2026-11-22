// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * An address confirmed by the holder's bank with a £0 card check
 * (services/card-check), as Personal Data and Import Data both offer it.
 * Explained first: a card check is unusual enough to say what happens, what is
 * charged (nothing) and what is kept (no card details).
 */

import { useState } from 'react';
import { Alert, Platform } from 'react-native';
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
            // The provider's page closes the same way whether the holder left
            // or their bank declined the check (it said so on its own page),
            // so the hint covers the decline without assuming one.
            if (e instanceof CardCheckError && e.reason === 'cancelled') {
                Alert.alert(t('cardCheck.declinedHint'));
                return;
            }
            if (e instanceof CardCheckError && e.reason === 'nothing-confirmed') {
                Alert.alert(`${t('cardCheck.nothingConfirmed')}\n\n${t('cardCheck.walletRetry')}`);
            } else {
                Alert.alert(t('cardCheck.failed', { reason: e?.message ?? String(e) }));
            }
        } finally {
            setBusy(false);
        }
    };

    // With Apple Pay or Google Pay the bank checks the address saved with the
    // card in the phone's wallet, not one typed on the page.
    const walletNote = t(Platform.OS === 'ios' ? 'cardCheck.walletNoteApple' : 'cardCheck.walletNoteGoogle');
    const start = () =>
        Alert.alert(t('cardCheck.explainTitle'), `${t('cardCheck.explainBody')}\n\n${walletNote}`, [
            { text: t('common.cancel'), style: 'cancel' },
            { text: t('common.continue'), onPress: () => void run() },
        ]);

    return { start, busy };
}
