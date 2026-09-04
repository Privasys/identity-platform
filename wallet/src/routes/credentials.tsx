// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Registered Credentials screen — the keys this device holds for the user's
 * accounts. Reached from Profile → Danger Zone: removing one is account
 * surgery, not a setting.
 *
 * Two kinds of credential, with very different removal consequences:
 *
 *  - IdP-brokered (rpId = privasys.id): the key to a PRIVASYS ACCOUNT. One
 *    rpId can carry several accounts (e.g. the platform identity and the
 *    canonical meta-account), so each row shows a short account id to tell
 *    them apart, and the one sign-ins actually use is badged. Removing one
 *    does NOT mean "re-register next time": the IdP's takeover protection
 *    makes a fresh registration mint a NEW, empty account — the old account
 *    (its apps, roles, vault approvals) is reachable again only through
 *    account recovery. This exact mistake orphaned the admin account on
 *    2026-07-30.
 *
 *  - Plain passkey RPs (rpId = the app's own host): a per-app passkey the
 *    wallet registered directly with that app. Removing it just means
 *    registering again on the next sign-in to that app.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useMemo } from 'react';
import { Alert, Pressable, ScrollView, StyleSheet } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { SubPageHeader } from '@/components/SubPageHeader';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Text, View, usePalette, type Palette } from '@/components/Themed';
import { useAuthStore, type Credential } from '@/stores/auth';
import { shortAccountId } from '@/utils/account-id';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

const IDP_RP = new URL(process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id').hostname;

/**
 * Short, stable account discriminator.
 *
 * Through shortAccountId, because the three call sites hand this three
 * different encodings of the same account: a credential's WebAuthn userHandle,
 * the meta-account slot's userId, and on older wallets that slot's raw hex.
 * Printing whichever arrived labelled the canonical account 'TnpRMU1E' while
 * the portal, the CLI and the sub claim all called it 'NzQ1MDQz', on the one
 * screen whose entire job is telling two accounts apart.
 */
function shortAccount(handleOrId: string | undefined, t: TFunction): string {
    const id = shortAccountId(handleOrId);
    if (!id) return t('credentials.unknownAccount');
    return t('credentials.accountShort', { id });
}

export default function CredentialsScreen() {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const { credentials, removeCredential, getCredentialForRp, privasysId } = useAuthStore();
    const { remove: removeTrustedApp } = useTrustedAppsStore();

    // The credential sign-ins actually select for the shared IdP RP
    // (newest-wins) — badge it so two same-rpId rows are distinguishable.
    const activeIdp = getCredentialForRp(IDP_RP);

    const removeOne = (cred: Credential) => {
        if (cred.rpId === IDP_RP) {
            const isActive = activeIdp?.credentialId === cred.credentialId;
            // Two complete messages rather than one assembled from clauses:
            // the "the one your sign-ins currently use" aside does not attach
            // to the same place in every language.
            Alert.alert(
                isActive
                    ? t('credentials.removeActiveKeyTitle')
                    : t('credentials.removeKeyTitle'),
                isActive
                    ? t('credentials.removeActiveKeyBody', { account: shortAccount(cred.userHandle, t) })
                    : t('credentials.removeKeyBody', { account: shortAccount(cred.userHandle, t) }),
                [
                    { text: t('common.cancel'), style: 'cancel' },
                    {
                        text: t('credentials.permanentlyRemove'),
                        style: 'destructive',
                        onPress: () => {
                            removeCredential(cred.credentialId);
                            removeTrustedApp(cred.rpId);
                        },
                    },
                ],
            );
            return;
        }
        Alert.alert(
            t('credentials.removeCredentialTitle'),
            t('credentials.removeCredentialBody', { host: cred.rpId }),
            [
                { text: t('common.cancel'), style: 'cancel' },
                {
                    text: t('common.remove'),
                    style: 'destructive',
                    onPress: () => {
                        removeCredential(cred.credentialId);
                        removeTrustedApp(cred.rpId);
                    },
                },
            ],
        );
    };

    const removeAll = () => {
        const idpCount = credentials.filter((c) => c.rpId === IDP_RP).length;
        Alert.alert(
            t('credentials.removeAllTitle'),
            idpCount > 0
                ? t('credentials.removeAllBodyWithAccounts', {
                    total: credentials.length,
                    count: idpCount
                })
                : t('credentials.removeAllBody', { count: credentials.length }),
            [
                { text: t('common.cancel'), style: 'cancel' },
                {
                    text: t('credentials.removeAll'),
                    style: 'destructive',
                    onPress: () => {
                        for (const cred of [...credentials]) {
                            removeCredential(cred.credentialId);
                            removeTrustedApp(cred.rpId);
                        }
                    },
                },
            ],
        );
    };

    return (
        <View style={styles.screen}>
            <SubPageHeader title={t('credentials.title')} />
            <ScrollView contentContainerStyle={[styles.content, { paddingBottom: insets.bottom + 24 }]}>
                {credentials.length === 0 && !privasysId ? (
                    <View style={styles.emptyCard}>
                        <Ionicons name="key-outline" size={32} color={p.textMuted} />
                        <Text style={styles.emptyText}>{t('credentials.empty')}</Text>
                    </View>
                ) : (
                    <>
                        <Text style={styles.intro}>{t('credentials.intro')}</Text>
                        {credentials.map((cred) => {
                            const isIdp = cred.rpId === IDP_RP;
                            const isActive = isIdp && activeIdp?.credentialId === cred.credentialId;
                            return (
                                <View key={cred.credentialId} style={styles.card}>
                                    <View style={styles.info}>
                                        <Text style={styles.rp}>
                                            {isIdp
                                                ? t('credentials.privasysAccount', {
                                                    account: shortAccount(cred.userHandle, t)
                                                })
                                                : cred.rpId}
                                        </Text>
                                        {isActive ? (
                                            <Text style={styles.activeBadge}>{t('credentials.activeBadge')}</Text>
                                        ) : isIdp ? (
                                            <Text style={styles.inactiveBadge}>{t('credentials.inactiveBadge')}</Text>
                                        ) : null}
                                        <Text style={styles.meta}>
                                            {t('credentials.registeredMeta', {
                                                user: cred.userName,
                                                when: new Date(cred.registeredAt * 1000)
                                            })}
                                        </Text>
                                    </View>
                                    <Pressable onPress={() => removeOne(cred)} hitSlop={8}>
                                        <Text style={styles.remove}>{t('common.remove')}</Text>
                                    </Pressable>
                                </View>
                            );
                        })}

                        {privasysId ? (
                            <View style={styles.card}>
                                <View style={styles.info}>
                                    <Text style={styles.rp}>
                                        {t('credentials.metaAccount', {
                                            account: shortAccount(privasysId.userId, t)
                                        })}
                                    </Text>
                                    <Text style={styles.meta}>{t('credentials.metaAccountHint')}</Text>
                                </View>
                            </View>
                        ) : null}

                        <Pressable style={styles.removeAll} onPress={removeAll}>
                            <Ionicons name="trash-outline" size={18} color={p.danger} />
                            <Text style={styles.removeAllText}>{t('credentials.removeAllTitle')}</Text>
                        </Pressable>
                    </>
                )}
            </ScrollView>
        </View>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    content: { padding: 20 },
    intro: { fontSize: 14, color: p.textSecondary, lineHeight: 20, marginBottom: 14 },
    emptyCard: {
        alignItems: 'center', justifyContent: 'center', backgroundColor: p.card,
        borderRadius: 12, padding: 24, gap: 8, marginTop: 8,
    },
    emptyText: { fontSize: 14, color: p.textMuted },
    card: {
        flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between',
        backgroundColor: p.card, borderRadius: 12, padding: 16, marginBottom: 8,
    },
    info: { flex: 1, backgroundColor: 'transparent' },
    rp: { fontSize: 15, fontWeight: '600', color: p.textPrimary, marginBottom: 2 },
    activeBadge: { fontSize: 12, color: p.green, fontWeight: '600', marginBottom: 2 },
    inactiveBadge: { fontSize: 12, color: p.textMuted, marginBottom: 2 },
    meta: { fontSize: 12, color: p.textSecondary },
    remove: { color: p.danger, fontSize: 14, fontWeight: '500' },
    removeAll: {
        flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8,
        backgroundColor: p.dangerBg, borderRadius: 12, paddingVertical: 14, marginTop: 12,
    },
    removeAllText: { color: p.danger, fontSize: 15, fontWeight: '600' },
});
