// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The holder's phones. Reached from Settings. This phone can be renamed; the
 * name shows on the holder's other phones and on the sign-in gate of browsers
 * it signs in to. Any phone can remove another at any time (a lost phone
 * included), and a phone can remove itself (services/device-flows), but not
 * when it is the only one: that would clear the only copy of the wallet.
 */

import { Ionicons } from '@expo/vector-icons';
import { useFocusEffect, useRouter } from 'expo-router';
import { useCallback, useMemo, useState } from 'react';
import { ActivityIndicator, Alert, KeyboardAvoidingView, Modal, Platform, Pressable, ScrollView, StyleSheet, TextInput, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { removeThisPhone, revokeDevice, type InstallProgress } from '@/services/device-flows';
import { MAX_DEVICES, listDevices, renameDevice, syncRegistry, type RegistryDevice } from '@/services/devices';
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
    const [renaming, setRenaming] = useState<string | null>(null);

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

    const saveName = async () => {
        const name = renaming ?? '';
        setRenaming(null);
        await renameDevice(name);
        setRows(await listDevices());
        try {
            await syncRegistry();
        } catch {
            /* reaches the other phones at the next sync */
        }
    };

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
                        {isThis ? (
                            <Pressable disabled={!!busy} onPress={() => setRenaming(device.name)} hitSlop={8}>
                                <Text style={styles.rename}>{t('devices.rename')}</Text>
                            </Pressable>
                        ) : (busy === device.id ? (
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

                {rows.length > 1 ? (
                    <Pressable style={styles.removeThis} disabled={!!busy} onPress={confirmRemoveThis}>
                        {busy === 'this' ? (
                            <ActivityIndicator color={p.danger} />
                        ) : (
                            <Text style={styles.removeThisText}>{t('devices.removeThis')}</Text>
                        )}
                    </Pressable>
                ) : null}
            </ScrollView>

            <Modal visible={renaming !== null} transparent animationType="fade" onRequestClose={() => setRenaming(null)}>
                <KeyboardAvoidingView style={styles.backdrop} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
                    <RNView style={styles.sheet}>
                        <Text style={styles.sheetTitle}>{t('devices.renameTitle')}</Text>
                        <Text style={styles.sheetBody}>{t('devices.renameBody')}</Text>
                        <TextInput
                            style={styles.input}
                            value={renaming ?? ''}
                            onChangeText={setRenaming}
                            maxLength={40}
                            autoFocus
                            selectTextOnFocus
                            returnKeyType="done"
                            onSubmitEditing={saveName}
                            placeholderTextColor={p.textMuted}
                        />
                        <RNView style={styles.sheetButtons}>
                            <Pressable onPress={() => setRenaming(null)} hitSlop={8}>
                                <Text style={styles.sheetCancel}>{t('common.cancel')}</Text>
                            </Pressable>
                            <Pressable onPress={saveName} hitSlop={8}>
                                <Text style={styles.sheetSave}>{t('common.save')}</Text>
                            </Pressable>
                        </RNView>
                    </RNView>
                </KeyboardAvoidingView>
            </Modal>
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
        rename: { color: p.action, fontSize: 14, fontWeight: '600' },
        backdrop: { flex: 1, justifyContent: 'center', padding: 24, backgroundColor: 'rgba(0,0,0,0.45)' },
        sheet: { backgroundColor: p.card, borderRadius: 16, padding: 20 },
        sheetTitle: { fontSize: 17, fontWeight: '700', color: p.textPrimary, marginBottom: 6 },
        sheetBody: { fontSize: 13.5, lineHeight: 19, color: p.textSecondary, marginBottom: 14 },
        input: {
            borderWidth: 1,
            borderColor: p.border,
            borderRadius: 10,
            paddingHorizontal: 12,
            paddingVertical: 10,
            fontSize: 16,
            color: p.textPrimary,
        },
        sheetButtons: { flexDirection: 'row', justifyContent: 'flex-end', gap: 24, marginTop: 18 },
        sheetCancel: { fontSize: 15, color: p.textSecondary },
        sheetSave: { fontSize: 15, fontWeight: '700', color: p.action },
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
