// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The pending account deletion, on every device of the holder: that it is
 * pending, when, a link to the page, and Cancel. Which apps hold data is shown
 * on the page only. Cancelling signs in afresh (the biometric prompt is the
 * confirmation) and unmarks every identity (services/account-deletion).
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, Alert, Linking, Pressable, StyleSheet, View as RNView } from 'react-native';
import { useTranslation } from 'react-i18next';

import { Text, usePalette, type Palette } from '@/components/Themed';
import {
    cancelDeletion,
    deletionDate,
    loadDeletionState,
    onDeletionState,
    pendingIdentityCount,
    type DeletionState,
} from '@/services/account-deletion';
import { notify } from '@/stores/notice';

export function AccountDeletionBanner() {
    const { t } = useTranslation();
    const router = useRouter();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const [state, setState] = useState<DeletionState>({ state: 'none' });
    const [waiting, setWaiting] = useState(0);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        let live = true;
        const show = (s: DeletionState) => {
            if (!live) return;
            setState(s);
            void pendingIdentityCount().then((n) => live && setWaiting(n));
        };
        void loadDeletionState().then(show);
        const off = onDeletionState(show);
        return () => {
            live = false;
            off();
        };
    }, []);

    if (state.state !== 'pending') return null;

    const days = state.deleteAt ? Math.max(0, Math.ceil((new Date(state.deleteAt).getTime() - Date.now()) / 86400000)) : null;

    const cancel = async () => {
        if (busy) return;
        setBusy(true);
        try {
            await cancelDeletion();
            notify(t('accountDeletion.cancelledTitle'), t('accountDeletion.cancelledBody'));
        } catch (e: any) {
            Alert.alert(t('accountDeletion.cancelFailed', { reason: e?.message ?? String(e) }));
        } finally {
            setBusy(false);
        }
    };

    return (
        <RNView style={styles.banner} testID="account-deletion-banner" accessibilityRole="alert">
            <RNView style={styles.head}>
                <Ionicons name="time-outline" size={20} color={p.danger} />
                <Text style={styles.title}>
                    {state.deleteAt
                        ? t('accountDeletion.bannerTitle', { date: deletionDate(new Date(state.deleteAt)) })
                        : t('accountDeletion.bannerTitleNoDate')}
                </Text>
            </RNView>
            {days !== null && <Text style={styles.body}>{t('accountDeletion.bannerDays', { count: days })}</Text>}
            {waiting > 0 && <Text style={styles.body}>{t('accountDeletion.bannerWaiting', { count: waiting })}</Text>}
            <RNView style={styles.actions}>
                <Pressable
                    style={[styles.cancel, busy && styles.idle]}
                    onPress={() => void cancel()}
                    disabled={busy}
                    testID="account-deletion-cancel"
                >
                    {busy ? (
                        <ActivityIndicator color="#FFFFFF" />
                    ) : (
                        <Text style={styles.cancelText}>{t('accountDeletion.bannerCancel')}</Text>
                    )}
                </Pressable>
                <Pressable style={styles.more} onPress={() => void Linking.openURL(state.pageUrl)}>
                    <Text style={styles.moreText}>{t('accountDeletion.bannerDetails')}</Text>
                </Pressable>
            </RNView>
            <Pressable onPress={() => router.push('/export')} hitSlop={8}>
                <Text style={styles.link}>{t('accountDeletion.saveCopy')}</Text>
            </Pressable>
        </RNView>
    );
}

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        banner: {
            backgroundColor: p.card,
            borderRadius: 14,
            borderWidth: 1,
            borderColor: p.danger,
            padding: 16,
            gap: 8,
            marginBottom: 16,
        },
        head: { flexDirection: 'row', alignItems: 'center', gap: 8 },
        title: { flex: 1, fontSize: 15, fontWeight: '700', color: p.textPrimary },
        body: { fontSize: 13.5, lineHeight: 19, color: p.textSecondary },
        actions: { flexDirection: 'row', gap: 10, marginTop: 4 },
        cancel: { flex: 1.35, paddingVertical: 12, borderRadius: 12, alignItems: 'center', backgroundColor: p.action },
        cancelText: { fontSize: 15, fontWeight: '600', color: '#FFFFFF' },
        more: { flex: 1, paddingVertical: 12, borderRadius: 12, alignItems: 'center', backgroundColor: p.buttonNeutral },
        moreText: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
        idle: { opacity: 0.5 },
        link: { fontSize: 14, fontWeight: '600', color: p.action, paddingTop: 4 },
    });
