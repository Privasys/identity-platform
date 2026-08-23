// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Secure your wallet — the dedicated recovery-phrase onboarding page.
 *
 * Shown as the step right after first-run wallet setup (and reachable
 * any time the phrase still needs setting up). One outcome-named
 * primary action creates the account session, mints the 24-word phrase
 * CLIENT-SIDE (only its hash reaches the server) and stores the
 * sovereign backup — the biometric prompt appears as a natural part of
 * the ceremony rather than being the button's label. The phrase is then
 * shown once, with copy/print actions and an explicit "I've saved it"
 * confirmation. Replaces the earlier popup-and-banner approach.
 */

import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import { useRouter } from 'expo-router';
import { useMemo, useState } from 'react';
import {
    ActivityIndicator,
    Alert,
    Pressable,
    ScrollView,
    Share,
    StyleSheet,
    View as RNView,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { useTranslation } from 'react-i18next';
import { ensurePrivasysSession } from '@/services/privasys-id';
import { establishPhraseWithBackup } from '@/services/sovereign';
import { useAuthStore } from '@/stores/auth';
import { useProfileStore } from '@/stores/profile';

export default function SecureWalletScreen() {
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const profile = useProfileStore((s) => s.profile);

    const [creating, setCreating] = useState(false);
    const [phrase, setPhrase] = useState<string | null>(null);
    const [backupError, setBackupError] = useState<string | null>(null);

    const handleCreate = async () => {
        setCreating(true);
        try {
            // The session dance (first registration or re-auth) triggers the
            // biometric prompt; the user asked for a phrase, and confirming
            // with biometrics is simply part of delivering it.
            const sess = await ensurePrivasysSession(profile?.displayName);
            const r = await establishPhraseWithBackup(
                sess.sessionToken,
                sess.recoveryPhrase ?? null,
                profile?.pairwiseSeed ?? null,
            );
            useAuthStore.getState().setRecoveryPhraseSaved(false);
            setPhrase(r.phrase);
            setBackupError(r.backupError ?? null);
        } catch (e: any) {
            Alert.alert(t('secureWallet.createFailed'), e?.message ?? String(e));
        } finally {
            setCreating(false);
        }
    };

    const handleSaved = () => {
        useAuthStore.getState().setRecoveryPhraseSaved(true);
        setPhrase(null);
        router.back();
    };

    return (
        <RNView style={styles.screen}>
            <RNView style={[styles.header, { paddingTop: insets.top + 8 }]}>
                <Pressable onPress={() => router.back()} hitSlop={12} style={styles.backButton}>
                    <Ionicons name="chevron-back" size={24} color="#FFFFFF" />
                </Pressable>
                <Text style={styles.headerTitle}>{t('secureWallet.title')}</Text>
                <RNView style={{ width: 32 }} />
            </RNView>

            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={styles.scrollContent}
                showsVerticalScrollIndicator={false}
            >
                {phrase ? (
                    <>
                        <RNView style={styles.card}>
                            <Text style={[styles.fieldLabel, { marginBottom: 8 }]}>
                                {t('secureWallet.saveWords')}
                            </Text>
                            <RNView style={styles.codesGrid}>
                                {phrase.split(/\s+/).map((word, i) => (
                                    <RNView key={i} style={styles.codeItem}>
                                        <Text style={styles.codeText}>{i + 1}. {word}</Text>
                                    </RNView>
                                ))}
                            </RNView>
                            <RNView style={{ flexDirection: 'row', gap: 10 }}>
                                <Pressable
                                    style={[styles.secondaryButton, { flex: 1 }]}
                                    onPress={async () => {
                                        await Clipboard.setStringAsync(phrase);
                                        Alert.alert(
                                            t('common.copied'),
                                            t('secureWallet.copiedWarning'),
                                        );
                                    }}
                                >
                                    <Text style={styles.secondaryButtonText}>{t('common.copy')}</Text>
                                </Pressable>
                                <Pressable
                                    style={[styles.secondaryButton, { flex: 1 }]}
                                    onPress={() => {
                                        void Share.share({ message: phrase });
                                    }}
                                >
                                    <Text style={styles.secondaryButtonText}>{t('secureWallet.sharePrint')}</Text>
                                </Pressable>
                            </RNView>
                            <Text style={styles.helperText}>{t('secureWallet.paperAdvice')}</Text>
                            <Pressable style={styles.primaryButton} onPress={handleSaved}>
                                <Text style={styles.primaryButtonText}>{t('secureWallet.savedIt')}</Text>
                            </Pressable>
                        </RNView>
                        {backupError && (
                            <RNView style={styles.warnCard}>
                                <Ionicons name="warning-outline" size={18} color="#F59E0B" />
                                <Text style={styles.warnText}>
                                    {t('secureWallet.backupFailed', { reason: backupError })}
                                </Text>
                            </RNView>
                        )}
                    </>
                ) : (
                    <>
                        <RNView style={styles.heroCard}>
                            <Ionicons name="key-outline" size={36} color={p.blue} />
                            <Text style={styles.heroTitle}>{t('secureWallet.heroTitle')}</Text>
                            <Text style={styles.heroText}>{t('secureWallet.heroBody')}</Text>
                        </RNView>
                        <RNView style={styles.card}>
                            <RNView style={styles.bulletRow}>
                                <Ionicons name="phone-portrait-outline" size={18} color={p.textMuted} />
                                <Text style={styles.bulletText}>{t('secureWallet.bulletOnDevice')}</Text>
                            </RNView>
                            <RNView style={styles.bulletRow}>
                                <Ionicons name="document-text-outline" size={18} color={p.textMuted} />
                                <Text style={styles.bulletText}>{t('secureWallet.bulletPaper')}</Text>
                            </RNView>
                            <RNView style={styles.bulletRow}>
                                <Ionicons name="shield-checkmark-outline" size={18} color={p.textMuted} />
                                <Text style={styles.bulletText}>{t('secureWallet.bulletBackup')}</Text>
                            </RNView>
                        </RNView>
                        <Pressable
                            style={[styles.primaryButton, creating && { opacity: 0.6 }]}
                            onPress={handleCreate}
                            disabled={creating}
                        >
                            {creating ? (
                                <ActivityIndicator color="#FFFFFF" size="small" />
                            ) : (
                                <Text style={styles.primaryButtonText}>{t('secureWallet.createPhrase')}</Text>
                            )}
                        </Pressable>
                        <Pressable onPress={() => router.back()} disabled={creating} hitSlop={8}>
                            <Text style={styles.laterText}>{t('secureWallet.later')}</Text>
                        </Pressable>
                    </>
                )}
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    header: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingHorizontal: 16,
        paddingBottom: 14,
        backgroundColor: '#0F172A',
    },
    backButton: { width: 32, alignItems: 'flex-start' },
    headerTitle: {
        fontSize: 18,
        fontWeight: '700',
        color: '#FFFFFF',
        letterSpacing: -0.3,
    },
    scrollView: { flex: 1 },
    scrollContent: { padding: 20, paddingBottom: 40 },
    heroCard: {
        alignItems: 'center',
        gap: 10,
        paddingVertical: 24,
        paddingHorizontal: 8,
    },
    heroTitle: {
        fontSize: 20,
        fontWeight: '700',
        color: p.textPrimary,
        textAlign: 'center',
        letterSpacing: -0.3,
    },
    heroText: {
        fontSize: 14,
        color: p.textMuted,
        textAlign: 'center',
        lineHeight: 20,
    },
    card: {
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 16,
        marginBottom: 16,
    },
    bulletRow: {
        flexDirection: 'row',
        alignItems: 'flex-start',
        gap: 10,
        marginVertical: 6,
    },
    bulletText: {
        flex: 1,
        fontSize: 13,
        color: p.textMuted,
        lineHeight: 18,
    },
    fieldLabel: {
        fontSize: 13,
        fontWeight: '600',
        color: p.textPrimary,
    },
    codesGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        gap: 6,
        marginBottom: 12,
    },
    codeItem: {
        backgroundColor: p.cardAlt,
        borderRadius: 6,
        paddingVertical: 6,
        paddingHorizontal: 10,
    },
    codeText: {
        fontSize: 13,
        fontFamily: 'Inter',
        color: p.textPrimary,
        fontWeight: '500',
        letterSpacing: 0.5,
    },
    helperText: {
        fontSize: 13,
        color: p.textMuted,
        lineHeight: 18,
        marginVertical: 12,
    },
    primaryButton: {
        backgroundColor: p.blue,
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center',
        justifyContent: 'center',
    },
    primaryButtonText: {
        fontSize: 16,
        fontWeight: '600',
        color: '#FFFFFF',
    },
    secondaryButton: {
        backgroundColor: p.cardAlt,
        borderRadius: 10,
        paddingVertical: 10,
        alignItems: 'center',
        justifyContent: 'center',
    },
    secondaryButtonText: {
        fontSize: 14,
        fontWeight: '600',
        color: p.textPrimary,
    },
    laterText: {
        fontSize: 14,
        color: p.textMuted,
        textAlign: 'center',
        marginTop: 16,
        textDecorationLine: 'underline',
    },
    warnCard: {
        flexDirection: 'row',
        alignItems: 'flex-start',
        gap: 10,
        backgroundColor: p.warnBg,
        borderRadius: 12,
        padding: 14,
    },
    warnText: {
        flex: 1,
        fontSize: 13,
        color: p.textPrimary,
        lineHeight: 18,
    },
});
