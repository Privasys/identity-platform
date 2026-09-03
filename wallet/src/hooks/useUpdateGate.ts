// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Drives the update gate: asks whether this build is still supported, and
 * re-asks when the app comes back to the foreground.
 *
 * Foreground matters more than launch. Someone told to update leaves for the
 * store and comes back, and the wall should be gone by then without a restart.
 * It is also the only re-check a wallet gets, since it is not an app people
 * leave running.
 *
 * Never blocks startup and never throws. The check is fire-and-forget and the
 * screen renders nothing until it has an answer, so a slow or absent network
 * costs the user nothing.
 */

import { useCallback, useEffect, useState } from 'react';
import { AppState, type AppStateStatus } from 'react-native';
import { useTranslation } from 'react-i18next';

import { checkForUpdate, dismissNotice, type UpdateNotice } from '@/services/app-version';

export function useUpdateGate(): { notice: UpdateNotice | null; dismiss: () => void } {
    const { i18n } = useTranslation();
    const [notice, setNotice] = useState<UpdateNotice | null>(null);
    const language = i18n.language;

    const run = useCallback(() => {
        void checkForUpdate(language)
            .then(setNotice)
            .catch(() => setNotice(null));
    }, [language]);

    useEffect(() => {
        run();
        const sub = AppState.addEventListener('change', (state: AppStateStatus) => {
            if (state === 'active') run();
        });
        return () => sub.remove();
    }, [run]);

    const dismiss = useCallback(() => {
        if (!notice) return;
        // Recorded so the same notice does not reappear on the next foreground.
        // `checkForUpdate` re-reads the record every time and ignores it for a
        // required notice, so this can never dismiss a wall.
        void dismissNotice(notice.id);
        setNotice(null);
    }, [notice]);

    return { notice, dismiss };
}
