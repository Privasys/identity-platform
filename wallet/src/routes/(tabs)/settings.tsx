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
import { StyleSheet, Pressable, Alert, ScrollView, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { ExternalLink } from '@/components/ExternalLink';
import { LanguagePicker } from '@/components/LanguagePicker';
import { Text, View, usePalette, type Palette } from '@/components/Themed';
import { useExpoPushToken } from '@/hooks/useExpoPushToken';
import { useSettingsStore, GRACE_OPTIONS } from '@/stores/settings';
import { getLogs } from '@/utils/logs';

export default function SettingsScreen() {
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { t } = useTranslation();
    const { gracePeriodSec, setGracePeriod } = useSettingsStore();
    const verificationMode = useSettingsStore((s) => s.verificationMode);
    const setVerificationMode = useSettingsStore((s) => s.setVerificationMode);
    const pushToken = useExpoPushToken();

    return (
        <RNView style={styles.screen}>
            <RNView style={[styles.header, { paddingTop: insets.top + 16 }]}>
                <Text style={styles.headerTitle}>{t('settings.title')}</Text>
            </RNView>

            <ScrollView style={styles.scroll} contentContainerStyle={styles.content}>
                <LanguagePicker />

                {/* Grace Period */}
                <Text style={styles.sectionTitle}>{t('settings.gracePeriodTitle')}</Text>
                <Text style={styles.sectionDescription}>{t('settings.gracePeriodDescription')}</Text>
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
                                {sec === 0
                                    ? t('settings.gracePeriodAlways')
                                    : t('settings.gracePeriodSeconds', { count: sec })}
                            </Text>
                        </Pressable>
                    ))}
                </View>

                {/* Enclave verification mode */}
                <Text style={styles.sectionTitle}>{t('settings.verificationTitle')}</Text>
                <Text style={styles.sectionDescription}>{t('settings.verificationDescription')}</Text>
                <View style={styles.optionsRow}>
                    {([
                        { key: 'deterministic', label: t('settings.verificationDeterministic') },
                        { key: 'challenge', label: t('settings.verificationChallenge') },
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

                {/* Registered credentials moved to Profile → Danger Zone:
                    removing one can permanently lock an account (re-registering
                    mints a NEW identity; the old one needs recovery), which is
                    account surgery, not a setting. */}

                {/* Push Token */}
                {pushToken ? (
                    <>
                        <Text style={styles.sectionTitle}>{t('settings.pushTokenTitle')}</Text>
                        <Pressable
                            style={styles.pushTokenCard}
                            onPress={() => {
                                Clipboard.setStringAsync(pushToken);
                                Alert.alert(t('common.copied'), t('settings.pushTokenCopied'));
                            }}
                        >
                            <Text style={styles.pushTokenText} numberOfLines={2}>
                                {pushToken}
                            </Text>
                            <Ionicons name="copy-outline" size={18} color={p.textSecondary} />
                        </Pressable>
                    </>
                ) : null}

                {/* Logs */}
                <Text style={styles.sectionTitle}>{t('settings.logsTitle')}</Text>
                <Text style={styles.sectionDescription}>
                    {t('settings.logsDescription', { count: getLogs().length })}
                </Text>
                <Pressable style={styles.logsButton} onPress={() => router.push('/logs')}>
                    <Ionicons name="document-text-outline" size={18} color={p.textPrimary} />
                    <Text style={styles.logsButtonText}>{t('settings.logsView')}</Text>
                    <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                </Pressable>

                {/* About — one tile: everything as key/value rows. */}
                <Text style={styles.sectionTitle}>{t('settings.aboutTitle')}</Text>
                <View style={styles.buildInfoCard}>
                    <BuildInfoRow label={t('settings.aboutVersion')} value={Constants.expoConfig?.extra?.CODE_VERSION} />
                    <BuildInfoRow label={t('settings.aboutBuildNumber')} value={Constants.expoConfig?.extra?.BUILD_NUMBER} />
                    <BuildInfoRow label={t('settings.aboutBuildId')} value={Constants.expoConfig?.extra?.BUILD_ID?.slice(0, 7)} />
                    <BuildInfoRow label={t('settings.aboutBuildType')} value={Constants.expoConfig?.extra?.STAGE} />
                    <BuildInfoRow label={t('settings.aboutCommitId')} value={Constants.expoConfig?.extra?.COMMIT_HASH?.slice(0, 7)} />
                    {/* Legal identity. A company name and its registration read
                        the same in every language and are never translated. */}
                    <BuildInfoRow label={t('settings.aboutDeveloper')} value="Privasys Ltd" />
                    <BuildInfoRow label={t('settings.aboutRegistered')} value="England & Wales" />
                    <BuildInfoRow label={t('settings.aboutCompanyNo')} value="16866500" />
                    <View style={styles.buildInfoRow}>
                        <Text style={styles.buildInfoLabel}>{t('settings.aboutWebsite')}</Text>
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
