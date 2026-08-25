// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Settings -> How connecting works.
 *
 * The same four cards the wallet shows before the first approval, on demand.
 * This is the only way back in once `seenFirstConnect` is set, so it is not
 * optional: a user who tapped Skip on their first connection has otherwise
 * lost the explanation permanently.
 *
 * No app name here — the standalone entry is not attached to a connection, so
 * the copy falls back to the generic noun rather than naming something the
 * user is not currently being asked about.
 */

import { Stack, useRouter } from 'expo-router';
import { View as RNView } from 'react-native';
import { useTranslation } from 'react-i18next';

import { FirstConnectExplainer } from '@/components/FirstConnectExplainer';
import { SubPageHeader } from '@/components/SubPageHeader';
import { usePalette } from '@/components/Themed';

export default function HowItWorksScreen() {
    const router = useRouter();
    const { t } = useTranslation();
    const p = usePalette();

    const leave = () => {
        if (router.canGoBack()) router.back();
        else router.replace('/(tabs)/settings');
    };

    return (
        <RNView style={{ flex: 1, backgroundColor: p.screenBg }}>
            <Stack.Screen options={{ headerShown: false }} />
            <SubPageHeader title={t('firstConnect.settingsRow')} />
            {/* No onSkip: the header's back button is the way out, and a
                "Skip" button here would have nothing to skip to. */}
            <FirstConnectExplainer onDone={leave} />
        </RNView>
    );
}
