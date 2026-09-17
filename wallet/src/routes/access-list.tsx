// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One group of standing grants in full, when the Access tab's preview of three
 * is not all of them.
 *
 * Parameterised by group rather than split into two screens: connected accounts
 * and access to the holder's own data differ in what revoking means, which is a
 * matter for the detail screen and the wording, not for the list.
 */

import { Ionicons } from '@expo/vector-icons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useMemo } from 'react';
import { Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { useCapabilitiesStore } from '@/stores/capabilities';
import { isLive, rowsInGroup, type AccessGroup } from '@/utils/access-rows';

export default function AccessListScreen() {
    const params = useLocalSearchParams<{ group?: string }>();
    const group: AccessGroup = params.group === 'account' ? 'account' : 'data';
    const records = useCapabilitiesStore((s) => s.records);
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { t } = useTranslation();

    const rows = useMemo(() => rowsInGroup(records, group), [records, group]);
    const nowSeconds = Math.floor(Date.now() / 1000);

    return (
        <RNView style={styles.screen}>
            <SubPageHeader
                title={t(group === 'account' ? 'access.accountsTitle' : 'access.dataTitle')}
            />
            <ScrollView
                contentContainerStyle={[styles.content, { paddingBottom: insets.bottom + 32 }]}
                showsVerticalScrollIndicator={false}
            >
                <Text style={styles.hint}>
                    {t(group === 'account' ? 'access.accountsHint' : 'access.dataHint')}
                </Text>
                <RNView style={styles.card}>
                    {rows.length === 0 ? (
                        <Text style={styles.empty}>
                            {t(group === 'account' ? 'access.accountsEmpty' : 'access.dataEmpty')}
                        </Text>
                    ) : (
                        rows.map((row) => {
                            const live = isLive(row.record, nowSeconds);
                            return (
                                <Pressable
                                    key={row.key}
                                    style={styles.row}
                                    onPress={() =>
                                        router.push({
                                            pathname: '/access-grant',
                                            params: { key: row.key },
                                        })
                                    }
                                >
                                    <RNView style={styles.rowInfo}>
                                        <Text style={[styles.rowTitle, !live && styles.ended]}>
                                            {row.record.appName || t('capability.unnamedApp')}
                                        </Text>
                                        <Text style={styles.rowMeta}>
                                            {group === 'account'
                                                ? row.record.resourceLabel
                                                : t('access.inService', {
                                                    resource: row.record.resourceLabel,
                                                    service:
                                                        row.record.resourceAppName ||
                                                        t('capability.unnamedApp'),
                                                })}
                                        </Text>
                                        {!live && (
                                            <Text style={styles.endedNote}>
                                                {row.record.revokedAt
                                                    ? t('access.stateRevoked')
                                                    : t('access.stateEnded')}
                                            </Text>
                                        )}
                                    </RNView>
                                    <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                                </Pressable>
                            );
                        })
                    )}
                </RNView>
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    content: { padding: 20 },
    hint: { fontSize: 13, color: p.textMuted, lineHeight: 19, marginBottom: 12 },
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
    empty: { fontSize: 13, color: p.textMuted, padding: 16 },
});
