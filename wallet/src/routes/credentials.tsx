// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Registered Credentials screen — lists the passkey credentials the wallet has
 * registered with relying parties, with per-credential removal and a
 * "Remove all" action. Moved out of the Settings tab into its own subpage.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useMemo } from 'react';
import { Alert, Pressable, ScrollView, StyleSheet } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, View, usePalette, type Palette } from '@/components/Themed';
import { useAuthStore } from '@/stores/auth';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

export default function CredentialsScreen() {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const { credentials, removeCredential } = useAuthStore();
    const { remove: removeTrustedApp } = useTrustedAppsStore();

    const removeOne = (credentialId: string, rpId: string) => {
        Alert.alert('Remove credential', `Remove the credential for ${rpId}?`, [
            { text: 'Cancel', style: 'cancel' },
            {
                text: 'Remove',
                style: 'destructive',
                onPress: () => {
                    removeCredential(credentialId);
                    removeTrustedApp(rpId);
                },
            },
        ]);
    };

    const removeAll = () => {
        Alert.alert(
            'Remove all credentials',
            `This removes all ${credentials.length} registered credentials and their trusted-app entries. You'll re-register on next sign-in. Continue?`,
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
                {credentials.length === 0 ? (
                    <View style={styles.emptyCard}>
                        <Ionicons name="key-outline" size={32} color={p.textMuted} />
                        <Text style={styles.emptyText}>No credentials registered yet</Text>
                    </View>
                ) : (
                    <>
                        <Text style={styles.intro}>
                            Passkey credentials this wallet has registered with apps. Removing one
                            means you'll register again next time you sign in to that app.
                        </Text>
                        {credentials.map((cred) => (
                            <View key={cred.credentialId} style={styles.card}>
                                <View style={styles.info}>
                                    <Text style={styles.rp}>{cred.rpId}</Text>
                                    <Text style={styles.meta}>
                                        {cred.userName} · Registered{' '}
                                        {new Date(cred.registeredAt * 1000).toLocaleDateString()}
                                    </Text>
                                </View>
                                <Pressable onPress={() => removeOne(cred.credentialId, cred.rpId)} hitSlop={8}>
                                    <Text style={styles.remove}>Remove</Text>
                                </Pressable>
                            </View>
                        ))}

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
    meta: { fontSize: 12, color: p.textSecondary },
    remove: { color: p.danger, fontSize: 14, fontWeight: '500' },
    removeAll: {
        flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8,
        backgroundColor: p.dangerBg, borderRadius: 12, paddingVertical: 14, marginTop: 12,
    },
    removeAllText: { color: p.danger, fontSize: 15, fontWeight: '600' },
});
