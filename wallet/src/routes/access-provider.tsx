// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One provider: everything the holder has connected there.
 *
 * The accounts (a level of their own only when there is more than one), under
 * each the products connected, under each product the apps using it. Each app
 * opens its own grant; "Disconnect <product>" ends every app's grant over that
 * product for that account, and "Disconnect this account" every grant over the
 * account. The sign-in the holder used to import details from this provider,
 * if any, sits here too, since it is the same account to them.
 *
 * Every word naming the provider or a product is what the service declared.
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
import { useProfileStore } from '@/stores/profile';
import { isLive } from '@/utils/access-rows';
import {
    liveIn,
    productNames,
    providerTree,
    recordsIn,
    withSignIns,
    type AccountNode,
    type ProductNode,
} from '@/utils/access-tree';

export default function AccessProviderScreen() {
    const params = useLocalSearchParams<{ key?: string }>();
    const key = String(params.key ?? '');
    const records = useCapabilitiesStore((s) => s.records);
    const linked = useProfileStore((s) => s.profile?.linkedProviders);
    const unlinkProvider = useProfileStore((s) => s.unlinkProvider);
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { t } = useTranslation();
    const [busy, setBusy] = useState(false);

    const provider = useMemo(
        () => withSignIns(providerTree(records), linked ?? []).find((x) => x.key === key),
        [records, linked, key],
    );
    const nowSeconds = Math.floor(Date.now() / 1000);

    if (!provider) {
        return (
            <RNView style={styles.screen}>
                <SubPageHeader title={t('access.accountsTitle')} />
                <RNView style={styles.centre}>
                    <Text style={styles.body}>{t('access.grantGone')}</Text>
                    <Pressable style={styles.secondary} onPress={() => router.back()}>
                        <Text style={styles.secondaryText}>{t('common.close')}</Text>
                    </Pressable>
                </RNView>
            </RNView>
        );
    }

    /**
     * Confirm, then end every live grant in the list. What the services could
     * not confirm stays listed, and the holder is told how much.
     */
    const disconnect = (title: string, body: string, targets: ProductNode | AccountNode) => {
        Alert.alert(title, body, [
            { text: t('common.cancel'), style: 'cancel' },
            {
                text: t('access.disconnect'),
                style: 'destructive',
                onPress: async () => {
                    setBusy(true);
                    try {
                        const outcome = await revokeRecords(recordsIn(targets));
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

    const forgetSignIn = () => {
        const signIn = provider.signIn;
        if (!signIn) return;
        const name = signIn.displayName || provider.name;
        Alert.alert(
            t('access.forgetSignInTitle', { provider: name }),
            t('access.forgetSignInBody', { provider: name }),
            [
                { text: t('common.cancel'), style: 'cancel' },
                {
                    text: t('access.forgetSignIn'),
                    style: 'destructive',
                    onPress: () => unlinkProvider(signIn.provider),
                },
            ],
        );
    };

    const several = provider.accounts.length > 1;

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={provider.name} />
            <ScrollView
                contentContainerStyle={[styles.content, { paddingBottom: insets.bottom + 32 }]}
                showsVerticalScrollIndicator={false}
            >
                {/* One account: its address under the provider's name, not a
                    level of its own. */}
                {!several && !!provider.accounts[0]?.account && (
                    <Text style={styles.lead}>{provider.accounts[0].account}</Text>
                )}

                {provider.signIn && (
                    <RNView style={styles.section}>
                        <Text style={styles.sectionTitle}>{t('access.signInTitle')}</Text>
                        <RNView style={styles.card}>
                            <RNView style={styles.cardBody}>
                                {!!provider.signIn.email && <Text style={styles.value}>{provider.signIn.email}</Text>}
                                <Text style={styles.muted}>
                                    {t('access.signInBody', { provider: provider.signIn.displayName || provider.name })}
                                </Text>
                            </RNView>
                            <Pressable style={styles.action} onPress={forgetSignIn} disabled={busy}>
                                <Text style={styles.actionText}>{t('access.forgetSignIn')}</Text>
                            </Pressable>
                        </RNView>
                    </RNView>
                )}

                {provider.accounts.map((account) => {
                    const accountLive = liveIn(recordsIn(account), nowSeconds) > 0;
                    return (
                        <RNView key={account.account} style={styles.account}>
                            {several && <Text style={styles.accountTitle}>{account.account || provider.name}</Text>}
                            {account.products.map((product) => {
                                const productLive = liveIn(recordsIn(product), nowSeconds) > 0;
                                return (
                                    <RNView key={product.key} style={styles.section}>
                                        <Text style={styles.sectionTitle}>{product.product}</Text>
                                        <RNView style={styles.card}>
                                            <Text style={styles.cardLabel}>{t('access.appsUsing')}</Text>
                                            {product.rows.map((row) => {
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
                                            })}
                                            {productLive && (
                                                <Pressable
                                                    style={styles.action}
                                                    disabled={busy}
                                                    onPress={() =>
                                                        disconnect(
                                                            t('access.disconnectProductTitle', { product: product.product }),
                                                            t('access.disconnectProductBody', {
                                                                product: product.product,
                                                                account: account.account,
                                                                provider: provider.name,
                                                            }),
                                                            product,
                                                        )
                                                    }
                                                >
                                                    <Text style={styles.actionText}>
                                                        {t('access.disconnectProduct', { product: product.product })}
                                                    </Text>
                                                </Pressable>
                                            )}
                                        </RNView>
                                    </RNView>
                                );
                            })}
                            {/* The whole account, when there is more than one
                                product on it; with one, the product's own
                                button already is this. */}
                            {accountLive && account.products.length > 1 && (
                                <Pressable
                                    style={styles.danger}
                                    disabled={busy}
                                    onPress={() =>
                                        disconnect(
                                            t('access.disconnectAccountTitle', { account: account.account }),
                                            t('access.disconnectAccountBody', {
                                                account: account.account,
                                                products: productNames(account).join(', '),
                                                provider: provider.name,
                                            }),
                                            account,
                                        )
                                    }
                                >
                                    <Text style={styles.dangerText}>{t('access.disconnectAccount')}</Text>
                                </Pressable>
                            )}
                        </RNView>
                    );
                })}

                {busy && <ActivityIndicator color={p.blue} style={styles.spinner} />}
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    content: { padding: 20 },
    centre: { alignItems: 'center', justifyContent: 'center', padding: 24, gap: 16 },
    body: { fontSize: 14, color: p.textSecondary, lineHeight: 21, textAlign: 'center' },
    lead: { fontSize: 15, color: p.textSecondary, marginBottom: 16 },
    account: { marginBottom: 8 },
    accountTitle: { fontSize: 17, fontWeight: '700', color: p.textPrimary, marginBottom: 10 },
    section: { marginBottom: 16 },
    sectionTitle: { fontSize: 13, fontWeight: '700', color: p.textMuted, letterSpacing: 0.4, marginBottom: 8 },
    card: { backgroundColor: p.card, borderRadius: 14, overflow: 'hidden' },
    cardBody: { padding: 16, gap: 6 },
    cardLabel: { fontSize: 12, color: p.textMuted, paddingHorizontal: 16, paddingTop: 12 },
    value: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
    muted: { fontSize: 13, color: p.textMuted, lineHeight: 19 },
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
    ended: { color: p.textMuted },
    endedNote: { fontSize: 12, color: p.textMuted },
    action: { paddingHorizontal: 16, paddingVertical: 13, alignItems: 'center' },
    actionText: { fontSize: 14, fontWeight: '600', color: p.danger },
    danger: {
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center',
        borderWidth: 1,
        borderColor: p.danger,
        marginBottom: 16,
    },
    dangerText: { fontSize: 15, fontWeight: '600', color: p.danger },
    secondary: { paddingVertical: 12, paddingHorizontal: 20 },
    secondaryText: { fontSize: 15, fontWeight: '600', color: p.blue },
    spinner: { marginTop: 8 },
});
