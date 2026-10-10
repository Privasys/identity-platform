// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Backup and export.
 *
 * The encrypted backup (services/profile-backup.ts): an automatic copy that
 * travels with the phone's own backup, a copy the holder saves anywhere, and a
 * restore from a file. Then the readable copy, the holder's details as a file
 * anyone can read, which is theirs to take (data portability); it is behind
 * the biometric and says plainly that it is unprotected.
 */

import { Ionicons } from '@expo/vector-icons';
import * as DocumentPicker from 'expo-document-picker';
import { File, Paths } from 'expo-file-system';
import * as LocalAuthentication from 'expo-local-authentication';
import * as Sharing from 'expo-sharing';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Pressable, ScrollView, StyleSheet, Switch, View as RNView } from 'react-native';
import { useTranslation } from 'react-i18next';

import { sectionTitleStyle } from '@/components/section-title';
import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { attributeLabel, exportAttributesForAudit } from '@/services/attributes';
import {
    BackupError,
    buildBackup,
    isAutoBackupOn,
    isDriveBackupOn,
    lastAutoBackupAt,
    lastDriveBackupAt,
    restoreFromDrive,
    restoreFromText,
    setAutoBackup,
    setDriveBackup,
} from '@/services/profile-backup';
import { useProfileStore } from '@/stores/profile';

export default function BackupAndExportScreen() {
    const { t, i18n } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { profile } = useProfileStore();
    const attrs = profile?.attributes ?? [];
    const [selected, setSelected] = useState<Set<string>>(() => new Set(attrs.map((a) => a.key)));
    const [autoOn, setAutoOn] = useState(true);
    const [lastAt, setLastAt] = useState<number | null>(null);
    const [driveOn, setDriveOn] = useState(false);
    const [lastDriveAt, setLastDriveAt] = useState<number | null>(null);
    const [busy, setBusy] = useState(false);

    const refreshAuto = useCallback(async () => {
        setAutoOn(await isAutoBackupOn());
        setLastAt(await lastAutoBackupAt());
        setDriveOn(await isDriveBackupOn());
        setLastDriveAt(await lastDriveBackupAt());
    }, []);
    useEffect(() => {
        void refreshAuto();
    }, [refreshAuto]);

    const toggleAuto = async (on: boolean) => {
        setAutoOn(on);
        await setAutoBackup(on);
        await refreshAuto();
    };

    const toggleDrive = async (on: boolean) => {
        setBusy(true);
        try {
            await setDriveBackup(on);
        } catch (e: any) {
            Alert.alert(
                t('backup.driveUnavailableTitle'),
                e instanceof BackupError && e.reason === 'no-drive' ? t('backup.driveUnavailableBody') : (e?.message ?? String(e)),
            );
        } finally {
            setBusy(false);
            await refreshAuto();
        }
    };

    const share = async (name: string, text: string, mimeType: string, uti: string) => {
        const file = new File(Paths.cache, name);
        if (file.exists) file.delete();
        file.create();
        file.write(text);
        await Sharing.shareAsync(file.uri, { mimeType, dialogTitle: t('export.dialogTitle'), UTI: uti });
    };

    const saveEncrypted = async () => {
        setBusy(true);
        try {
            const stamp = new Date().toISOString().slice(0, 10);
            await share(`privasys-wallet-backup-${stamp}.json`, await buildBackup(), 'application/json', 'public.json');
        } catch (e: any) {
            Alert.alert(t('export.failed'), e?.message ?? String(e));
        } finally {
            setBusy(false);
        }
    };

    const restore = async () => {
        try {
            const picked = await DocumentPicker.getDocumentAsync({
                type: ['application/json', 'text/plain', '*/*'],
                copyToCacheDirectory: true,
                multiple: false,
            });
            if (picked.canceled || !picked.assets?.[0]) return;
            setBusy(true);
            const text = await new File(picked.assets[0].uri).text();
            restored(await restoreFromText(text));
        } catch (e: any) {
            restoreFailed(e);
        } finally {
            setBusy(false);
        }
    };

    const restoreDrive = async () => {
        setBusy(true);
        try {
            restored(await restoreFromDrive());
        } catch (e: any) {
            restoreFailed(e);
        } finally {
            setBusy(false);
        }
    };

    const restored = (r: { attributes: number; records: number }) =>
        Alert.alert(t('backup.restoredTitle'), t('backup.restoredBody', { attributes: r.attributes, records: r.records }));

    const restoreFailed = (e: any) => {
        const reason = e instanceof BackupError ? e.reason : null;
        const body =
            reason === 'not-a-backup'
                ? t('backup.errNotBackup')
                : reason === 'wrong-wallet'
                  ? t('backup.errWrongWallet')
                  : reason === 'no-root' || reason === 'no-profile'
                    ? t('backup.errRecoverFirst')
                    : reason === 'no-drive'
                      ? t('backup.driveUnavailableBody')
                      : reason === 'none-in-drive'
                        ? t('backup.errNoDriveBackup')
                        : (e?.message ?? String(e));
        Alert.alert(t('backup.restoreFailedTitle'), body);
    };

    const toggle = (key: string) =>
        setSelected((prev) => {
            const next = new Set(prev);
            if (next.has(key)) next.delete(key);
            else next.add(key);
            return next;
        });

    // The readable copy is unprotected by design: say so, and ask for the
    // biometric, so it is never one stray tap away.
    const exportReadable = (keys: Set<string>) => {
        if (!profile) return;
        Alert.alert(t('backup.readableWarnTitle'), t('backup.readableWarnBody'), [
            { text: t('common.cancel'), style: 'cancel' },
            {
                text: t('common.continue'),
                onPress: async () => {
                    try {
                        const auth = await LocalAuthentication.authenticateAsync({
                            promptMessage: t('backup.readableConfirm'),
                        });
                        if (!auth.success) return;
                        const data = exportAttributesForAudit(profile);
                        data.attributes = data.attributes.filter((a) => keys.has(a.key));
                        await share(
                            `privasys-profile-${Date.now()}.json`,
                            JSON.stringify(data, null, 2),
                            'application/json',
                            'public.json',
                        );
                    } catch (e: any) {
                        Alert.alert(t('export.failed'), e?.message ?? String(e));
                    }
                },
            },
        ]);
    };

    const count = attrs.filter((a) => selected.has(a.key)).length;
    const lastLabel = lastAt
        ? t('backup.autoLast', {
              when: new Date(lastAt * 1000).toLocaleString(i18n.language, { dateStyle: 'medium', timeStyle: 'short' }),
          })
        : t('backup.autoNever');

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('backup.title')} />
            <ScrollView contentContainerStyle={styles.content}>
                <Text style={styles.sectionTitle}>{t('backup.autoTitle')}</Text>
                <RNView style={styles.row}>
                    <RNView style={{ flex: 1 }}>
                        <Text style={styles.rowLabel}>{t('backup.autoTitle')}</Text>
                        <Text style={styles.rowValue}>{autoOn ? lastLabel : ''}</Text>
                    </RNView>
                    <Switch value={autoOn} onValueChange={(v) => void toggleAuto(v)} />
                </RNView>
                <Text style={styles.intro}>{t('backup.autoHint')}</Text>

                <Pressable style={[styles.primary, busy && styles.disabled]} onPress={saveEncrypted} disabled={busy}>
                    <Ionicons name="lock-closed-outline" size={18} color="#FFFFFF" />
                    <Text style={styles.primaryText}>{t('backup.saveEncrypted')}</Text>
                </Pressable>
                <Text style={styles.hint}>{t('backup.saveEncryptedHint')}</Text>
                <Pressable style={styles.secondary} onPress={restore} disabled={busy}>
                    <Text style={styles.secondaryText}>{t('backup.restore')}</Text>
                </Pressable>

                <RNView style={[styles.row, { marginTop: 8 }]}>
                    <RNView style={{ flex: 1 }}>
                        <Text style={styles.rowLabel}>{t('backup.driveTitle')}</Text>
                        {driveOn && lastDriveAt ? (
                            <Text style={styles.rowValue}>
                                {t('backup.driveLast', {
                                    when: new Date(lastDriveAt * 1000).toLocaleString(i18n.language, {
                                        dateStyle: 'medium',
                                        timeStyle: 'short',
                                    }),
                                })}
                            </Text>
                        ) : null}
                    </RNView>
                    <Switch value={driveOn} onValueChange={(v) => void toggleDrive(v)} disabled={busy} />
                </RNView>
                <Text style={styles.hint}>{t('backup.driveHint')}</Text>
                {driveOn ? (
                    <Pressable style={styles.secondary} onPress={restoreDrive} disabled={busy}>
                        <Text style={styles.secondaryText}>{t('backup.restoreFromDrive')}</Text>
                    </Pressable>
                ) : null}

                <Text style={styles.sectionTitle}>{t('backup.readableTitle')}</Text>
                <Text style={styles.intro}>{t('backup.readableHint')}</Text>
                {attrs.length === 0 ? (
                    <Text style={styles.empty}>{t('backup.noAttributes')}</Text>
                ) : (
                    <>
                        {attrs.map((attr) => (
                            <Pressable key={attr.key} style={styles.row} onPress={() => toggle(attr.key)}>
                                <RNView style={{ flex: 1 }}>
                                    <Text style={styles.rowLabel}>{attributeLabel(attr.key)}</Text>
                                    <Text style={styles.rowValue} numberOfLines={1}>
                                        {attr.key === 'picture' ? t('import.profilePhoto') : attr.value}
                                    </Text>
                                </RNView>
                                <Switch value={selected.has(attr.key)} onValueChange={() => toggle(attr.key)} />
                            </Pressable>
                        ))}
                        <Pressable
                            style={[styles.primary, count === 0 && styles.disabled]}
                            onPress={() => exportReadable(selected)}
                            disabled={count === 0}
                        >
                            <Ionicons name="share-outline" size={18} color="#FFFFFF" />
                            <Text style={styles.primaryText}>{t('export.exportCount', { count })}</Text>
                        </Pressable>
                        <Pressable
                            style={styles.secondary}
                            onPress={() => exportReadable(new Set(attrs.map((a) => a.key)))}
                        >
                            <Text style={styles.secondaryText}>{t('backup.exportAll')}</Text>
                        </Pressable>
                    </>
                )}
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        screen: { flex: 1, backgroundColor: p.screenBg },
        content: { padding: 20, paddingBottom: 48 },
        sectionTitle: { ...sectionTitleStyle(p), marginTop: 16, marginBottom: 8 },
        intro: { fontSize: 14, color: p.textSecondary, lineHeight: 20, marginBottom: 12 },
        hint: { fontSize: 13, color: p.textMuted, lineHeight: 19, marginTop: 8 },
        empty: { fontSize: 14, color: p.textMuted, textAlign: 'center', marginTop: 8 },
        row: {
            flexDirection: 'row',
            alignItems: 'center',
            gap: 12,
            backgroundColor: p.card,
            borderRadius: 12,
            paddingHorizontal: 16,
            paddingVertical: 12,
            marginBottom: 8,
        },
        rowLabel: { fontSize: 15, fontWeight: '500', color: p.textPrimary },
        rowValue: { fontSize: 12, color: p.textMuted, marginTop: 1 },
        primary: {
            flexDirection: 'row',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 8,
            backgroundColor: p.blue,
            borderRadius: 12,
            paddingVertical: 14,
            marginTop: 12,
        },
        primaryText: { color: '#FFFFFF', fontSize: 15, fontWeight: '600' },
        disabled: { opacity: 0.5 },
        secondary: { paddingVertical: 12, alignItems: 'center' },
        secondaryText: { color: p.blue, fontSize: 14, fontWeight: '500' },
    });
