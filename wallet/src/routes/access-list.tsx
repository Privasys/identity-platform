// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Every provider, or every app, when the Access tab's preview of three is not
 * all of them.
 *
 * Parameterised by group rather than split into two screens: the two lists are
 * two ways in to the same grants, and each row opens its own screen.
 */

import { useLocalSearchParams, useRouter } from 'expo-router';
import { useMemo } from 'react';
import { ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { AppRow, ProviderRow } from '@/components/AccessRows';
import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { useCapabilitiesStore } from '@/stores/capabilities';
import { useProfileStore } from '@/stores/profile';
import { appTree, providerTree, withSignIns } from '@/utils/access-tree';

export default function AccessListScreen() {
    const params = useLocalSearchParams<{ group?: string }>();
    const byProvider = params.group === 'account';
    const records = useCapabilitiesStore((s) => s.records);
    const linked = useProfileStore((s) => s.profile?.linkedProviders);
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { t } = useTranslation();

    const providers = useMemo(() => withSignIns(providerTree(records), linked ?? []), [records, linked]);
    const apps = useMemo(() => appTree(records), [records]);
    const nowSeconds = Math.floor(Date.now() / 1000);
    const empty = byProvider ? providers.length === 0 : apps.length === 0;

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t(byProvider ? 'access.accountsTitle' : 'access.dataTitle')} />
            <ScrollView
                contentContainerStyle={[styles.content, { paddingBottom: insets.bottom + 32 }]}
                showsVerticalScrollIndicator={false}
            >
                <Text style={styles.hint}>{t(byProvider ? 'access.providersHint' : 'access.appsHint')}</Text>
                <RNView style={styles.card}>
                    {empty ? (
                        <Text style={styles.empty}>
                            {t(byProvider ? 'access.accountsEmpty' : 'access.dataEmpty')}
                        </Text>
                    ) : byProvider ? (
                        providers.map((provider) => (
                            <ProviderRow
                                key={provider.key}
                                provider={provider}
                                nowSeconds={nowSeconds}
                                onPress={() =>
                                    router.push({ pathname: '/access-provider', params: { key: provider.key } })
                                }
                                styles={styles}
                                p={p}
                            />
                        ))
                    ) : (
                        apps.map((app) => (
                            <AppRow
                                key={app.appId}
                                app={app}
                                nowSeconds={nowSeconds}
                                onPress={() => router.push({ pathname: '/access-app', params: { appId: app.appId } })}
                                styles={styles}
                                p={p}
                            />
                        ))
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
    rowEnded: { color: p.textMuted },
    rowEndedNote: { fontSize: 12, color: p.textMuted },
    empty: { fontSize: 13, color: p.textMuted, padding: 16 },
});
