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
import { Text, View, usePalette, type Palette } from '@/components/Themed';
import { useAuthStore, type Credential } from '@/stores/auth';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

const IDP_RP = new URL(process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id').hostname;

/** Short, stable account discriminator from the credential's userHandle. */
function shortAccount(userHandle: string | undefined): string {
    if (!userHandle) return 'unknown account';
    return `account ${userHandle.slice(0, 8)}…`;
}

export default function CredentialsScreen() {
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
            Alert.alert(
                isActive ? 'Remove your account key?' : 'Remove an account key?',
                `This is the key to your Privasys ${shortAccount(cred.userHandle)}` +
                    (isActive ? ', the one your sign-ins currently use.' : '.') +
                    '\n\nRemoving it permanently discards this device’s only way to ' +
                    'prove that identity. Signing in again will NOT restore it: a new ' +
                    'registration creates a NEW, empty account. Everything bound to ' +
                    'this account (app ownership, roles, vault approvals) stays ' +
                    'locked until you run account recovery with its recovery phrase.' +
                    '\n\nOnly remove this if you are certain the account is disposable ' +
                    'or safely held elsewhere.',
                [
                    { text: 'Cancel', style: 'cancel' },
                    {
                        text: 'Permanently remove key',
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
            'Remove credential',
            `Remove the passkey for ${cred.rpId}? You will register again the next ` +
                'time you sign in to that app; anything stored under your current ' +
                'identity there may not carry over.',
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Remove',
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
            'Remove all credentials',
            `This removes all ${credentials.length} credentials` +
                (idpCount > 0
                    ? `, including ${idpCount} Privasys account key${idpCount > 1 ? 's' : ''}. ` +
                      'Those accounts become unreachable until account recovery: a fresh ' +
                      'sign-in creates new, empty identities, not the old ones.'
                    : '.') +
                ' Continue?',
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Remove all',
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
            <SubPageHeader title="Registered Credentials" />
            <ScrollView contentContainerStyle={[styles.content, { paddingBottom: insets.bottom + 24 }]}>
                {credentials.length === 0 && !privasysId ? (
                    <View style={styles.emptyCard}>
                        <Ionicons name="key-outline" size={32} color={p.textMuted} />
                        <Text style={styles.emptyText}>No credentials registered yet</Text>
                    </View>
                ) : (
                    <>
                        <Text style={styles.intro}>
                            The keys this device holds. Privasys account keys cannot be
                            re-created by signing in again. Removing one locks that
                            account until recovery.
                        </Text>
                        {credentials.map((cred) => {
                            const isIdp = cred.rpId === IDP_RP;
                            const isActive = isIdp && activeIdp?.credentialId === cred.credentialId;
                            return (
                                <View key={cred.credentialId} style={styles.card}>
                                    <View style={styles.info}>
                                        <Text style={styles.rp}>
                                            {isIdp ? `Privasys ${shortAccount(cred.userHandle)}` : cred.rpId}
                                        </Text>
                                        {isActive ? (
                                            <Text style={styles.activeBadge}>
                                                Active: your sign-ins use this key
                                            </Text>
                                        ) : isIdp ? (
                                            <Text style={styles.inactiveBadge}>
                                                Not used for sign-ins (other account)
                                            </Text>
                                        ) : null}
                                        <Text style={styles.meta}>
                                            {cred.userName} · Registered{' '}
                                            {new Date(cred.registeredAt * 1000).toLocaleDateString()}
                                        </Text>
                                    </View>
                                    <Pressable onPress={() => removeOne(cred)} hitSlop={8}>
                                        <Text style={styles.remove}>Remove</Text>
                                    </Pressable>
                                </View>
                            );
                        })}

                        {privasysId ? (
                            <View style={styles.card}>
                                <View style={styles.info}>
                                    <Text style={styles.rp}>
                                        Privasys ID meta-{shortAccount(privasysId.userId)}
                                    </Text>
                                    <Text style={styles.meta}>
                                        Your wallet&apos;s own account (recovery management).
                                        Managed automatically, not removable here.
                                    </Text>
                                </View>
                            </View>
                        ) : null}

                        <Pressable style={styles.removeAll} onPress={removeAll}>
                            <Ionicons name="trash-outline" size={18} color={p.danger} />
                            <Text style={styles.removeAllText}>Remove all credentials</Text>
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
