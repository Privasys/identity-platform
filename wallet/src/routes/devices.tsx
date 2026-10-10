// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The holder's phones. Reached from Settings, which shows the entry only when
 * there is more than one. Any phone can remove another at any time (a lost
 * phone included), and a phone can remove itself (services/device-flows).
 */

import { Ionicons } from '@expo/vector-icons';
import { useFocusEffect, useRouter } from 'expo-router';
import { useCallback, useMemo, useState } from 'react';
import { ActivityIndicator, Alert, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { removeThisPhone, revokeDevice, type InstallProgress } from '@/services/device-flows';
import { MAX_DEVICES, listDevices, syncRegistry, type RegistryDevice } from '@/services/devices';
import { wipeWallet } from '@/services/wipe';

type Row = { device: RegistryDevice; isThis: boolean };

export default function DevicesScreen() {
    const { t, i18n } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const router = useRouter();

    const [rows, setRows] = useState<Row[]>([]);
    const [busy, setBusy] = useState<string | null>(null);
    const [progress, setProgress] = useState<InstallProgress | null>(null);

    const load = useCallback(async () => {
        setRows(await listDevices());
        try {
            await syncRegistry();
            setRows(await listDevices());
        } catch {
            /* the list on this phone is shown */
        }
    }, []);

    useFocusEffect(
        useCallback(() => {
            void load();
        }, [load]),
    );

    const added = (d: RegistryDevice) =>
        t('devices.added', {
            date: new Date(d.createdAt * 1000).toLocaleDateString(i18n.language, { day: 'numeric', month: 'long', year: 'numeric' }),
        });

    const confirmRevoke = (d: RegistryDevice) =>
        Alert.alert(t('devices.revokeTitle', { name: d.name }), t('devices.revokeBody'), [
            { text: t('common.cancel'), style: 'cancel' },
            {
                text: t('devices.revokeConfirm'),
                style: 'destructive',
                onPress: async () => {
                    setBusy(d.id);
                    setProgress(null);
                    try {
                        const r = await revokeDevice(d, setProgress);
                        Alert.alert(
                            r.failed > 0
                                ? t('devices.revokePartial', { name: d.name, count: r.failed })
                                : t('devices.revoked', { name: d.name }),
                        );
                    } catch (e: any) {
                        Alert.alert(t('devices.revokeFailed', { reason: e?.message ?? String(e) }));
                    } finally {
                        setBusy(null);
                        void load();
                    }
                },
            },
        ]);

    const confirmRemoveThis = () =>
        Alert.alert(t('devices.removeThisTitle'), t('devices.removeThisBody'), [
            { text: t('common.cancel'), style: 'cancel' },
            {
                text: t('devices.removeThisConfirm'),
                style: 'destructive',
                onPress: async () => {
                    setBusy('this');
                    try {
                        await removeThisPhone();
                        await wipeWallet();
                        router.replace('/(tabs)');
                    } catch (e: any) {
                        Alert.alert(t('devices.revokeFailed', { reason: e?.message ?? String(e) }));
                    } finally {
                        setBusy(null);
                    }
                },
            },
        ]);

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('devices.title')} />
            <ScrollView contentContainerStyle={[styles.body, { paddingBottom: insets.bottom + 32 }]}>
                <Text style={styles.lede}>{t('devices.lede')}</Text>
                {rows.map(({ device, isThis }) => (
                    <RNView key={device.id} style={styles.card}>
                        <Ionicons name="phone-portrait-outline" size={22} color={p.textSecondary} />
                        <RNView style={styles.cardText}>
                            <Text style={styles.name}>{device.name}</Text>
                            <Text style={styles.meta}>{isThis ? t('devices.thisPhone') : added(device)}</Text>
                        </RNView>
                        {!isThis &&
                            (busy === device.id ? (
                                <RNView style={styles.busy}>
                                    <ActivityIndicator color={p.danger} />
                                    {progress && progress.identities > 0 ? (
                                        <Text style={styles.meta}>
                                            {t('devices.revoking', {
                                                done: progress.done + progress.failed,
                                                total: progress.identities,
                                            })}
                                        </Text>
                                    ) : null}
                                </RNView>
                            ) : (
                                <Pressable disabled={!!busy} onPress={() => confirmRevoke(device)} hitSlop={8}>
                                    <Text style={styles.remove}>{t('devices.revoke')}</Text>
                                </Pressable>
                            ))}
                    </RNView>
                ))}

                <Text style={styles.note}>{t('devices.addHint')}</Text>
                <Text style={styles.note}>{t('devices.limitNote', { max: MAX_DEVICES })}</Text>

                <Pressable style={styles.removeThis} disabled={!!busy} onPress={confirmRemoveThis}>
                    {busy === 'this' ? (
                        <ActivityIndicator color={p.danger} />
                    ) : (
                        <Text style={styles.removeThisText}>{t('devices.removeThis')}</Text>
                    )}
                </Pressable>
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        screen: { flex: 1, backgroundColor: p.screenBg },
        body: { padding: 20, paddingTop: 20 },
        lede: { fontSize: 14, lineHeight: 20, color: p.textSecondary, marginBottom: 16 },
        card: {
            flexDirection: 'row',
            alignItems: 'center',
            gap: 14,
            backgroundColor: p.card,
            borderRadius: 12,
            padding: 16,
            marginBottom: 8,
        },
        cardText: { flex: 1 },
        name: { fontSize: 15, fontWeight: '600', color: p.textPrimary, marginBottom: 2 },
        meta: { fontSize: 12.5, color: p.textSecondary },
        busy: { alignItems: 'flex-end', gap: 4 },
        remove: { color: p.danger, fontSize: 14, fontWeight: '600' },
        note: { marginTop: 14, fontSize: 13, lineHeight: 19, color: p.textMuted },
        removeThis: {
            marginTop: 28,
            borderRadius: 14,
            borderWidth: 1,
            borderColor: p.danger,
            paddingVertical: 14,
            alignItems: 'center',
        },
        removeThisText: { color: p.danger, fontSize: 15, fontWeight: '600' },
    });
