// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Settings tab — wallet configuration plus the About/version section that
 * used to live in its own tab.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import * as Clipboard from 'expo-clipboard';
import Constants from 'expo-constants';
import { useRouter } from 'expo-router';
import { StyleSheet, Pressable, Alert, ScrollView, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import AboutPrivasysWallet from '@/components/AboutPrivasysWallet';
import { Text, View, Image } from '@/components/Themed';
import { useExpoPushToken } from '@/hooks/useExpoPushToken';
import { useAuthStore } from '@/stores/auth';
import { useSettingsStore, GRACE_OPTIONS } from '@/stores/settings';
import { useTrustedAppsStore } from '@/stores/trusted-apps';
import { getLogs } from '@/utils/logs';

export default function SettingsScreen() {
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const { credentials, removeCredential } = useAuthStore();
    const { gracePeriodSec, setGracePeriod } = useSettingsStore();
    const { remove: removeTrustedApp } = useTrustedAppsStore();
    const pushToken = useExpoPushToken();

    return (
        <RNView style={styles.screen}>
            <RNView style={[styles.header, { paddingTop: insets.top + 16 }]}>
                <Text style={styles.headerTitle}>Settings</Text>
            </RNView>

            <ScrollView style={styles.scroll} contentContainerStyle={styles.content}>
                {/* Grace Period */}
                <Text style={styles.sectionTitle}>Biometric Grace Period</Text>
                <Text style={styles.sectionDescription}>
                    After authenticating once, skip the biometric prompt for subsequent requests
                    within this window.
                </Text>
                <View style={styles.optionsRow}>
                    {GRACE_OPTIONS.map((sec) => (
                        <Pressable
                            key={sec}
                            style={[
                                styles.optionButton,
                                gracePeriodSec === sec && styles.optionButtonActive
                            ]}
                            onPress={() => setGracePeriod(sec)}
                        >
                            <Text
                                style={[
                                    styles.optionText,
                                    gracePeriodSec === sec && styles.optionTextActive
                                ]}
                            >
                                {sec === 0 ? 'Always' : `${sec}s`}
                            </Text>
                        </Pressable>
                    ))}
                </View>

                {/* Registered Credentials */}
                <Text style={styles.sectionTitle}>Registered Credentials</Text>
                {credentials.length === 0 ? (
                    <View style={styles.emptyCard}>
                        <Ionicons name="key-outline" size={32} color="#C7C7CC" />
                        <Text style={styles.emptyText}>No credentials registered yet</Text>
                    </View>
                ) : (
                    credentials.map((cred) => (
                        <View key={cred.credentialId} style={styles.credentialCard}>
                            <View style={styles.credentialInfo}>
                                <Text style={styles.credentialRp}>{cred.rpId}</Text>
                                <Text style={styles.credentialMeta}>
                                    {cred.userName} · Registered{' '}
                                    {new Date(cred.registeredAt * 1000).toLocaleDateString()}
                                </Text>
                            </View>
                            <Pressable
                                onPress={() =>
                                    Alert.alert(
                                        'Remove Credential',
                                        `Remove credential for ${cred.rpId}?`,
                                        [
                                            { text: 'Cancel', style: 'cancel' },
                                            {
                                                text: 'Remove',
                                                style: 'destructive',
                                                onPress: () => {
                                                    removeCredential(cred.credentialId);
                                                    removeTrustedApp(cred.rpId);
                                                }
                                            }
                                        ]
                                    )
                                }
                            >
                                <Text style={styles.removeButton}>Remove</Text>
                            </Pressable>
                        </View>
                    ))
                )}

                {/* Push Token */}
                {pushToken ? (
                    <>
                        <Text style={styles.sectionTitle}>Push Token</Text>
                        <Pressable
                            style={styles.pushTokenCard}
                            onPress={() => {
                                Clipboard.setStringAsync(pushToken);
                                Alert.alert('Copied', 'Push token copied to clipboard.');
                            }}
                        >
                            <Text style={styles.pushTokenText} numberOfLines={2}>
                                {pushToken}
                            </Text>
                            <Ionicons name="copy-outline" size={18} color="#64748B" />
                        </Pressable>
                    </>
                ) : null}

                {/* About */}
                <Text style={styles.sectionTitle}>About</Text>
                <View style={styles.aboutCard}>
                    <AboutPrivasysWallet />
                </View>

                <View style={styles.buildInfoCard}>
                    <BuildInfoRow label="Version" value={Constants.expoConfig?.extra?.CODE_VERSION} />
                    <BuildInfoRow label="Build Number" value={Constants.expoConfig?.extra?.BUILD_NUMBER} />
                    <BuildInfoRow label="Build ID" value={Constants.expoConfig?.extra?.BUILD_ID?.slice(0, 7)} />
                    <BuildInfoRow label="Build Type" value={Constants.expoConfig?.extra?.STAGE} />
                    <BuildInfoRow label="Commit ID" value={Constants.expoConfig?.extra?.COMMIT_HASH?.slice(0, 7)} />
                </View>

                {/* Logs */}
                <Text style={styles.sectionTitle}>Logs</Text>
                <Text style={styles.sectionDescription}>
                    The wallet captures the most recent console output in memory so you can share
                    it when reporting issues. Currently {getLogs().length} entries.
                </Text>
                <Pressable style={styles.logsButton} onPress={() => router.push('/logs')}>
                    <Ionicons name="document-text-outline" size={18} color="#0F172A" />
                    <Text style={styles.logsButtonText}>View Logs</Text>
                    <Ionicons name="chevron-forward" size={18} color="#94A3B8" />
                </Pressable>
            </ScrollView>
        </RNView>
    );
}

function BuildInfoRow({ label, value }: { label: string; value?: string }) {
    return (
        <View style={styles.buildInfoRow}>
            <Text style={styles.buildInfoLabel}>{label}</Text>
            <Text style={styles.buildInfoValue}>{value ?? '-'}</Text>
        </View>
    );
}

const styles = StyleSheet.create({
    screen: { flex: 1, backgroundColor: '#F8FAFB' },
    header: {
        backgroundColor: '#34E89E',
        paddingHorizontal: 24,
        paddingBottom: 24,
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28
    },
    headerTitle: {
        fontSize: 28,
        fontWeight: '700',
        color: '#FFFFFF',
        letterSpacing: -0.5
    },
    scroll: { flex: 1 },
    content: { padding: 20, paddingTop: 16, paddingBottom: 40 },
    sectionTitle: {
        fontSize: 17,
        fontWeight: '600',
        color: '#0F172A',
        marginTop: 24,
        marginBottom: 6
    },
    sectionDescription: {
        fontSize: 14,
        color: '#64748B',
        marginBottom: 14,
        lineHeight: 20
    },
    emptyCard: {
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 24,
        gap: 8,
        marginBottom: 8
    },
    emptyText: { fontSize: 14, color: '#C7C7CC' },

    optionsRow: {
        flexDirection: 'row',
        gap: 8,
        marginBottom: 12,
        backgroundColor: 'transparent'
    },
    optionButton: {
        flex: 1,
        paddingVertical: 10,
        borderRadius: 10,
        backgroundColor: '#FFFFFF',
        alignItems: 'center',
        borderWidth: 1,
        borderColor: '#E2E8F0'
    },
    optionButtonActive: {
        backgroundColor: '#007AFF',
        borderColor: '#007AFF'
    },
    optionText: { fontSize: 15, fontWeight: '500', color: '#0F172A' },
    optionTextActive: { color: '#fff' },

    credentialCard: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 8
    },
    credentialInfo: { flex: 1, backgroundColor: 'transparent' },
    credentialRp: { fontSize: 15, fontWeight: '600', color: '#0F172A', marginBottom: 2 },
    credentialMeta: { fontSize: 12, color: '#64748B' },
    removeButton: { color: '#FF3B30', fontSize: 14, fontWeight: '500' },

    pushTokenCard: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12,
        backgroundColor: '#F1F5F9',
        borderRadius: 12,
        padding: 14,
        marginBottom: 8
    },
    pushTokenText: {
        flex: 1,
        fontSize: 12,
        fontFamily: 'SpaceMono',
        color: '#64748B',
        lineHeight: 18
    },

    aboutCard: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 12
    },
    aboutHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12,
        backgroundColor: 'transparent'
    },
    aboutLogo: { width: 36, height: 36, backgroundColor: 'transparent' },
    aboutTitle: { fontSize: 16, fontWeight: '600', color: '#0F172A' },
    aboutSeparator: { height: 1, marginVertical: 12 },

    buildInfoCard: {
        backgroundColor: '#F1F5F9',
        borderRadius: 12,
        padding: 16,
        gap: 10
    },
    buildInfoRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        backgroundColor: 'transparent'
    },
    buildInfoLabel: { fontSize: 14, color: '#64748B' },
    buildInfoValue: { fontSize: 14, fontWeight: '600', color: '#0F172A' },

    logsButton: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12,
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        paddingHorizontal: 14,
        paddingVertical: 14,
        marginBottom: 8,
    },
    logsButtonText: { flex: 1, fontSize: 15, fontWeight: '500', color: '#0F172A' },
});
