// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One app, and everything it can use.
 *
 * Grouped by who holds it: each provider the holder connected an account at,
 * and each Privasys service holding their own data. Each line opens its grant.
 * "Remove everything" ends every grant this app holds, one at its service
 * after another; accounts other apps use stay connected for them.
 */

import { Ionicons } from '@expo/vector-icons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useMemo, useState } from 'react';
import { ActivityIndicator, Alert, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { revokeRecords } from '@/services/access-revoke';
import { useCapabilitiesStore } from '@/stores/capabilities';
import { isLive, type AccessRow } from '@/utils/access-rows';
import { appTree, liveIn, whatOf } from '@/utils/access-tree';

export default function AccessAppScreen() {
    const params = useLocalSearchParams<{ appId?: string }>();
    const appId = String(params.appId ?? '');
    const records = useCapabilitiesStore((s) => s.records);
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { t } = useTranslation();
    const [busy, setBusy] = useState(false);

    const app = useMemo(() => appTree(records).find((a) => a.appId === appId), [records, appId]);
    const nowSeconds = Math.floor(Date.now() / 1000);

    // By who holds it: the provider a service declared, or the service itself.
    const groups = useMemo(() => {
        const out: { name: string; rows: AccessRow[] }[] = [];
        for (const row of app?.rows ?? []) {
            const r = row.record;
            const name = r.providerName || r.resourceAppName || t('capability.unnamedApp');
            let g = out.find((x) => x.name === name);
            if (!g) {
                g = { name, rows: [] };
                out.push(g);
            }
            g.rows.push(row);
        }
        return out.sort((a, b) => a.name.localeCompare(b.name));
    }, [app, t]);

    if (!app) {
        return (
            <RNView style={styles.screen}>
                <SubPageHeader title={t('access.dataTitle')} />
                <RNView style={styles.centre}>
                    <Text style={styles.body}>{t('access.grantGone')}</Text>
                    <Pressable style={styles.secondary} onPress={() => router.back()}>
                        <Text style={styles.secondaryText}>{t('common.close')}</Text>
                    </Pressable>
                </RNView>
            </RNView>
        );
    }

    const name = app.appName || t('capability.unnamedApp');
    const all = app.rows.map((r) => r.record);

    const removeAll = () => {
        Alert.alert(t('access.removeAppTitle', { app: name }), t('access.removeAppBody', { app: name }), [
            { text: t('common.cancel'), style: 'cancel' },
            {
                text: t('access.remove'),
                style: 'destructive',
                onPress: async () => {
                    setBusy(true);
                    try {
                        const outcome = await revokeRecords(all);
                        if (outcome.failed.length > 0) {
                            Alert.alert(
                                t('access.bulkPartialTitle'),
                                t('access.bulkPartialBody', { failed: outcome.failed.length }),
                            );
                        }
                    } finally {
                        setBusy(false);
                    }
                },
            },
        ]);
    };

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={name} />
            <ScrollView
                contentContainerStyle={[styles.content, { paddingBottom: insets.bottom + 32 }]}
                showsVerticalScrollIndicator={false}
            >
                <Text style={styles.mono}>{app.appId}</Text>

                {groups.map((group) => (
                    <RNView key={group.name} style={styles.section}>
                        <Text style={styles.sectionTitle}>{group.name}</Text>
                        <RNView style={styles.card}>
                            {group.rows.map((row) => {
                                const r = row.record;
                                const live = isLive(r, nowSeconds);
                                const meta = r.account
                                    ? r.account
                                    : r.product
                                      ? r.resourceLabel
                                      : t('access.inService', {
                                          resource: r.resourceLabel,
                                          service: r.resourceAppName || t('capability.unnamedApp'),
                                      });
                                return (
                                    <Pressable
                                        key={row.key}
                                        style={styles.row}
                                        onPress={() =>
                                            router.push({ pathname: '/access-grant', params: { key: row.key } })
                                        }
                                    >
                                        <RNView style={styles.rowInfo}>
                                            <Text style={[styles.rowTitle, !live && styles.ended]}>{whatOf(r)}</Text>
                                            {meta !== whatOf(r) && <Text style={styles.rowMeta}>{meta}</Text>}
                                            {!live && (
                                                <Text style={styles.endedNote}>
                                                    {r.revokedAt ? t('access.stateRevoked') : t('access.stateEnded')}
                                                </Text>
                                            )}
                                        </RNView>
                                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                                    </Pressable>
                                );
                            })}
                        </RNView>
                    </RNView>
                ))}

                {liveIn(all, nowSeconds) > 0 && (
                    <Pressable style={styles.danger} onPress={removeAll} disabled={busy}>
                        {busy ? (
                            <ActivityIndicator color={p.danger} />
                        ) : (
                            <Text style={styles.dangerText}>{t('access.removeApp')}</Text>
                        )}
                    </Pressable>
                )}
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    content: { padding: 20 },
    centre: { alignItems: 'center', justifyContent: 'center', padding: 24, gap: 16 },
    body: { fontSize: 14, color: p.textSecondary, lineHeight: 21, textAlign: 'center' },
    mono: { fontSize: 12, fontFamily: 'SpaceMono', color: p.textMuted, marginBottom: 16 },
    section: { marginBottom: 16 },
    sectionTitle: { fontSize: 13, fontWeight: '700', color: p.textMuted, letterSpacing: 0.4, marginBottom: 8 },
    card: { backgroundColor: p.card, borderRadius: 14, overflow: 'hidden' },
    row: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        paddingHorizontal: 16,
        paddingVertical: 14,
        borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: p.border,
    },
    rowInfo: { flex: 1, gap: 2 },
    rowTitle: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
    rowMeta: { fontSize: 13, color: p.textSecondary },
    ended: { color: p.textMuted },
    endedNote: { fontSize: 12, color: p.textMuted },
    danger: {
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center',
        borderWidth: 1,
        borderColor: p.danger,
        marginTop: 8,
    },
    dangerText: { fontSize: 15, fontWeight: '600', color: p.danger },
    secondary: { paddingVertical: 12, paddingHorizontal: 20 },
    secondaryText: { fontSize: 15, fontWeight: '600', color: p.blue },
});
