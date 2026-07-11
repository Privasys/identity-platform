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
import { useMemo } from 'react';
import { StyleSheet, Pressable, Alert, ScrollView, Switch, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { ExternalLink } from '@/components/ExternalLink';
import { Text, View, usePalette, type Palette } from '@/components/Themed';
import { useExpoPushToken } from '@/hooks/useExpoPushToken';
import { useAuthStore } from '@/stores/auth';
import { useSettingsStore, GRACE_OPTIONS } from '@/stores/settings';
import { getLogs } from '@/utils/logs';

export default function SettingsScreen() {
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { credentials } = useAuthStore();
    const { gracePeriodSec, setGracePeriod } = useSettingsStore();
    const driveEnabled = useSettingsStore((s) => s.driveEnabled);
    const setDriveEnabled = useSettingsStore((s) => s.setDriveEnabled);
    const verificationMode = useSettingsStore((s) => s.verificationMode);
    const setVerificationMode = useSettingsStore((s) => s.setVerificationMode);
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

                {/* Enclave verification mode */}
                <Text style={styles.sectionTitle}>Enclave Verification</Text>
                <Text style={styles.sectionDescription}>
                    Deterministic is fast and checks the enclave against the attestation service.
                    Challenge additionally sends a fresh random number each time so the enclave
                    proves it is live and bound to this exact session. You can always challenge a
                    single enclave from its approval screen.
                </Text>
                <View style={styles.optionsRow}>
                    {([
                        { key: 'deterministic', label: 'Deterministic' },
                        { key: 'challenge', label: 'Challenge' },
                    ] as const).map((opt) => (
                        <Pressable
                            key={opt.key}
                            style={[
                                styles.optionButton,
                                verificationMode === opt.key && styles.optionButtonActive
                            ]}
                            onPress={() => setVerificationMode(opt.key)}
                        >
                            <Text
                                style={[
                                    styles.optionText,
                                    verificationMode === opt.key && styles.optionTextActive
                                ]}
                            >
                                {opt.label}
                            </Text>
                        </Pressable>
                    ))}
                </View>

                {/* Registered Credentials → subpage */}
                <Text style={styles.sectionTitle}>Registered Credentials</Text>
                <Pressable style={styles.logsButton} onPress={() => router.push('/credentials' as never)}>
                    <Ionicons name="key-outline" size={18} color={p.textPrimary} />
                    <Text style={styles.logsButtonText}>
                        Manage Credentials{credentials.length > 0 ? ` (${credentials.length})` : ''}
                    </Text>
                    <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                </Pressable>

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
                            <Ionicons name="copy-outline" size={18} color={p.textSecondary} />
                        </Pressable>
                    </>
                ) : null}

                {/* Experimental */}
                <Text style={styles.sectionTitle}>Experimental</Text>
                <RNView style={styles.toggleRow}>
                    <RNView style={{ flex: 1 }}>
                        <Text style={styles.toggleLabel}>Drive (preview)</Text>
                        <Text style={styles.toggleHint}>Your confidential personal drive. In progress.</Text>
                    </RNView>
                    <Switch
                        value={driveEnabled}
                        onValueChange={setDriveEnabled}
                        trackColor={{ true: p.green, false: p.border }}
                    />
                </RNView>

                {/* Logs */}
                <Text style={styles.sectionTitle}>Logs</Text>
                <Text style={styles.sectionDescription}>
                    The wallet captures the most recent console output in memory so you can share
                    it when reporting issues. Currently {getLogs().length} entries.
                </Text>
                <Pressable style={styles.logsButton} onPress={() => router.push('/logs')}>
                    <Ionicons name="document-text-outline" size={18} color={p.textPrimary} />
                    <Text style={styles.logsButtonText}>View Logs</Text>
                    <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                </Pressable>

                {/* About — one tile: everything as key/value rows. */}
                <Text style={styles.sectionTitle}>About</Text>
                <View style={styles.buildInfoCard}>
                    <BuildInfoRow label="Version" value={Constants.expoConfig?.extra?.CODE_VERSION} />
                    <BuildInfoRow label="Build Number" value={Constants.expoConfig?.extra?.BUILD_NUMBER} />
                    <BuildInfoRow label="Build ID" value={Constants.expoConfig?.extra?.BUILD_ID?.slice(0, 7)} />
                    <BuildInfoRow label="Build Type" value={Constants.expoConfig?.extra?.STAGE} />
                    <BuildInfoRow label="Commit ID" value={Constants.expoConfig?.extra?.COMMIT_HASH?.slice(0, 7)} />
                    <BuildInfoRow label="Developer" value="Privasys Ltd" />
                    <BuildInfoRow label="Registered" value="England & Wales" />
                    <BuildInfoRow label="Company No." value="16866500" />
                    <View style={styles.buildInfoRow}>
                        <Text style={styles.buildInfoLabel}>Website</Text>
                        <ExternalLink href="https://privasys.org">
                            <Text style={styles.buildInfoLink}>privasys.org</Text>
                        </ExternalLink>
                    </View>
                </View>
            </ScrollView>
        </RNView>
    );
}

function BuildInfoRow({ label, value }: { label: string; value?: string }) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    return (
        <View style={styles.buildInfoRow}>
            <Text style={styles.buildInfoLabel}>{label}</Text>
            <Text style={styles.buildInfoValue}>{value ?? '-'}</Text>
        </View>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    header: {
        backgroundColor: p.green,
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
        color: p.textPrimary,
        marginTop: 24,
        marginBottom: 6
    },
    sectionDescription: {
        fontSize: 14,
        color: p.textSecondary,
        marginBottom: 14,
        lineHeight: 20
    },
    emptyCard: {
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 24,
        gap: 8,
        marginBottom: 8
    },
    emptyText: { fontSize: 14, color: p.textMuted },

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
        backgroundColor: p.card,
        alignItems: 'center',
        borderWidth: 1,
        borderColor: p.border
    },
    optionButtonActive: {
        backgroundColor: p.action,
        borderColor: p.action
    },
    optionText: { fontSize: 15, fontWeight: '500', color: p.textPrimary },
    optionTextActive: { color: '#fff' },

    credentialCard: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 16,
        marginBottom: 8
    },
    credentialInfo: { flex: 1, backgroundColor: 'transparent' },
    credentialRp: { fontSize: 15, fontWeight: '600', color: p.textPrimary, marginBottom: 2 },
    credentialMeta: { fontSize: 12, color: p.textSecondary },
    removeButton: { color: p.danger, fontSize: 14, fontWeight: '500' },

    pushTokenCard: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12,
        backgroundColor: p.cardAlt,
        borderRadius: 12,
        padding: 14,
        marginBottom: 8
    },
    pushTokenText: {
        flex: 1,
        fontSize: 12,
        fontFamily: 'SpaceMono',
        color: p.textSecondary,
        lineHeight: 18
    },

    buildInfoCard: {
        backgroundColor: p.cardAlt,
        borderRadius: 12,
        padding: 16,
        gap: 10
    },
    buildInfoRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        backgroundColor: 'transparent'
    },
    buildInfoLabel: { fontSize: 14, color: p.textSecondary },
    buildInfoValue: { fontSize: 14, fontWeight: '600', color: p.textPrimary },
    buildInfoLink: { fontSize: 14, fontWeight: '600', color: p.blue },

    logsButton: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12,
        backgroundColor: p.card,
        borderRadius: 12,
        paddingHorizontal: 14,
        paddingVertical: 14,
        marginBottom: 8,
    },
    logsButtonText: { flex: 1, fontSize: 15, fontWeight: '500', color: p.textPrimary },
    toggleRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12,
        backgroundColor: p.card,
        borderRadius: 12,
        paddingHorizontal: 14,
        paddingVertical: 12,
        marginBottom: 8,
    },
    toggleLabel: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
    toggleHint: { fontSize: 12, color: p.textSecondary, marginTop: 2 },
});
