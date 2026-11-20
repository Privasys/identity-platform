// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The one-time question about the app lock (services/app-lock), asked after
 * setup or on the first start of a version that has it. Either answer is kept,
 * and Settings changes it later.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { unlockWallet } from '@/components/AppLock';
import { SubPageHeader } from '@/components/SubPageHeader';
import { taskStyles } from '@/components/task-styles';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { APP_LOCK_DEFAULT } from '@/services/app-lock';
import { biometricLabelKey, DEFAULT_BIOMETRIC_LABEL_KEY } from '@/services/biometrics';
import { useSettingsStore } from '@/stores/settings';

export default function AppLockQuestion() {
    const { t } = useTranslation();
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const [labelKey, setLabelKey] = useState(DEFAULT_BIOMETRIC_LABEL_KEY);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        void biometricLabelKey().then(setLabelKey);
        // Asked once: going back without an answer is a "not now".
        useSettingsStore.getState().setAppLockAsked();
    }, []);

    const leave = () => {
        if (router.canGoBack()) router.back();
        else router.replace('/');
    };

    const notNow = () => {
        useSettingsStore.getState().setAppLockAsked();
        leave();
    };

    // Turning it on checks Face ID once, so the holder knows it works before
    // the wallet relies on it.
    const turnOn = async () => {
        if (busy) return;
        setBusy(true);
        try {
            if (!(await unlockWallet(t('appLock.prompt'), t('common.cancel')))) return;
            const settings = useSettingsStore.getState();
            settings.setAppLock(APP_LOCK_DEFAULT);
            settings.setAppLockAsked();
            leave();
        } finally {
            setBusy(false);
        }
    };

    return (
        <RNView style={styles.screen} testID="app-lock-question">
            <SubPageHeader title={t('appLock.title')} />
            <ScrollView contentContainerStyle={[styles.body, { paddingBottom: insets.bottom + 32 }]}>
                <RNView style={styles.card}>
                    <RNView style={styles.metaRow}>
                        <Ionicons name="lock-closed-outline" size={18} color={p.textSecondary} />
                        <Text style={styles.cardTitle}>{t('appLock.offerHeading')}</Text>
                    </RNView>
                    <Text style={styles.lineValue}>{t('appLock.offerBody', { biometric: t(labelKey) })}</Text>
                </RNView>
                <RNView style={styles.actions}>
                    <Pressable
                        style={[styles.declineButton, busy && styles.buttonIdle]}
                        disabled={busy}
                        onPress={notNow}
                        accessibilityRole="button"
                        testID="app-lock-not-now"
                    >
                        <Text style={styles.declineButtonText}>{t('common.notNow')}</Text>
                    </Pressable>
                    <Pressable
                        style={[styles.affirmButton, busy && styles.buttonIdle]}
                        disabled={busy}
                        onPress={() => void turnOn()}
                        accessibilityRole="button"
                        testID="app-lock-turn-on"
                    >
                        <Text style={styles.affirmButtonText}>{t('appLock.turnOn')}</Text>
                    </Pressable>
                </RNView>
                <Text style={styles.note}>{t('appLock.offerNote')}</Text>
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => ({
    ...taskStyles(p),
    ...StyleSheet.create({
        cardTitle: { flex: 1, fontSize: 15, fontWeight: '600', color: p.textPrimary },
    }),
});
