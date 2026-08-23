// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Profile tab — view and manage identity, personal data, and consent history.
 */

import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import * as LocalAuthentication from 'expo-local-authentication';
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import {
    StyleSheet,
    ScrollView,
    Pressable,
    View as RNView,
    Alert,
    ActivityIndicator,
    Image,
    Platform,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { Text, usePalette, type Palette } from '@/components/Themed';
import {
    biometricLabelKey,
    titleiseBiometric,
    DEFAULT_BIOMETRIC_LABEL_KEY,
} from '@/services/biometrics';
import { getDeviceLocale } from '@/services/device-locale';
import { ensureDeviceKey, generateDid, generatePairwiseSeed, generateCanonicalDid } from '@/services/did';
import { clearSovereignLocalState, takeRecoveredPairwiseSeed } from '@/services/sovereign';
import { useAuthStore } from '@/stores/auth';
import { useConsentStore } from '@/stores/consent';
import { useProfileStore } from '@/stores/profile';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

export default function ProfileScreen() {
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { profile, clearProfile } =
        useProfileStore();
    const { credentials, removeCredential } = useAuthStore();
    const recoveryPhraseSaved = useAuthStore((s) => s.recoveryPhraseSaved);
    const { apps, remove: removeTrustedApp } = useTrustedAppsStore();
    const consentRecordCount = useConsentStore((s) => s.records.length);

    const setOnboarded = useAuthStore((s) => s.setOnboarded);
    // First-run setup progress: 0 = not started, then one tick per milestone
    // (biometric confirmed → key created → identity ready).
    const [setupBusy, setSetupBusy] = useState(false);
    const [setupDone, setSetupDone] = useState(0);
    // Platform-appropriate name for the device unlock ("Face ID", "fingerprint",
    // ...), so Android fingerprint users are never told to "Set up Face ID".
    const { t } = useTranslation();
    // The KEY is held in state, not the resolved string: a language change
    // must re-render this label, and a stored string would not.
    const [bioKey, setBioKey] = useState(DEFAULT_BIOMETRIC_LABEL_KEY);
    const bioLabel = t(bioKey);
    useEffect(() => {
        let alive = true;
        void biometricLabelKey().then((l) => {
            if (alive) setBioKey(l);
        });
        return () => {
            alive = false;
        };
    }, []);

    /**
     * First-run wallet setup: confirm the user's biometrics, create the
     * hardware-backed device key (the one that signs the DID and all KYC / WIA
     * proofs), then derive the identity and the local profile. This is the only
     * guaranteed key-creation point now that the standalone onboarding screen is
     * gone, so it runs here and, lazily, on the sign-in path.
     */
    const handleSetup = async () => {
        setSetupBusy(true);
        setSetupDone(0);
        try {
            // 1 — Confirm biometrics exist, are enrolled, and actually work.
            const hasHardware = await LocalAuthentication.hasHardwareAsync();
            const enrolled = hasHardware && (await LocalAuthentication.isEnrolledAsync());
            if (!enrolled) {
                Alert.alert(
                    t('profile.setupBiometricFirstTitle', { method: bioLabel }),
                    t(
                        Platform.OS === 'ios'
                            ? 'profile.setupBiometricFirstBodyIos'
                            : 'profile.setupBiometricFirstBodyAndroid',
                        { method: bioLabel }
                    )
                );
                setSetupBusy(false);
                return;
            }
            const auth = await LocalAuthentication.authenticateAsync({
                promptMessage: t('profile.setupPrompt'),
                fallbackLabel: t('profile.usePasscode'),
                cancelLabel: t('common.cancel')
            });
            if (!auth.success) {
                setSetupBusy(false);
                return;
            }
            setSetupDone(1);

            // 2 — Create the biometric-gated signing key inside secure hardware.
            await ensureDeviceKey();
            setSetupDone(2);

            // 3 — Derive the identity and create the on-device profile. A
            // seed recovered from the sovereign backup (account recovery on
            // this device) takes precedence over minting a fresh one — that
            // is what carries pairwise identities across devices.
            const did = await generateDid();
            const pairwiseSeed = (await takeRecoveredPairwiseSeed()) ?? (await generatePairwiseSeed());
            const canonicalDid = await generateCanonicalDid(pairwiseSeed);
            useProfileStore.getState().createProfile({
                displayName: t('profile.defaultDisplayName'),
                email: '',
                avatarUri: '',
                locale: getDeviceLocale(),
                did,
                canonicalDid,
                pairwiseSeed,
                linkedProviders: [],
                attributes: []
            });
            setOnboarded();
            setSetupDone(3);
            // Release the ceremony state even though the profile view takes
            // over: the component stays MOUNTED, so a later "Clear All Data"
            // brings this screen back — with a stale busy=true the button
            // spun forever and the wallet was unusable (2026-08-22).
            setSetupBusy(false);
            // The setup flow continues onto its second page: the dedicated
            // recovery-phrase step (a real screen, not a popup). It carries
            // its own "later" escape for users who insist.
            router.push('/secure-wallet');
        } catch (e: any) {
            Alert.alert(
                t('profile.setupFailedTitle'),
                t('profile.setupFailedBody', { reason: e.message })
            );
            setSetupBusy(false);
            setSetupDone(0);
        }
    };

    if (!profile) {
        const setupItems = [
            {
                icon: 'scan-outline' as const,
                title: t('profile.setupUnlockTitle'),
                body: t(
                    Platform.OS === 'ios'
                        ? 'profile.setupUnlockBodyIos'
                        : 'profile.setupUnlockBodyAndroid',
                    { method: titleiseBiometric(bioLabel) }
                )
            },
            {
                icon: 'hardware-chip-outline' as const,
                title: t('profile.setupHardwareTitle'),
                body: t('profile.setupHardwareBody')
            },
            {
                icon: 'finger-print-outline' as const,
                title: t('profile.setupIdentityTitle'),
                body: t('profile.setupIdentityBody')
            }
        ];
        return (
            <RNView style={[styles.screen, { paddingTop: insets.top }]}>
                <ScrollView contentContainerStyle={styles.setupScroll} showsVerticalScrollIndicator={false}>
                    <RNView style={styles.setupHeader}>
                        <Ionicons name="shield-checkmark-outline" size={56} color={p.green} />
                        <Text style={styles.setupTitle}>{t('profile.setupTitle')}</Text>
                        <Text style={styles.setupLede}>{t('profile.setupLede')}</Text>
                    </RNView>

                    {/* What this creates — each row ticks green as that step completes. */}
                    <RNView style={styles.setupCard}>
                        {setupItems.map((it, i) => {
                            const done = i < setupDone;
                            const active = setupBusy && i === setupDone;
                            return (
                                <RNView key={it.title} style={styles.setupRow}>
                                    <RNView style={[styles.setupBubble, done && styles.setupBubbleDone]}>
                                        {done ? (
                                            <Ionicons name="checkmark" size={16} color="#FFFFFF" />
                                        ) : active ? (
                                            <ActivityIndicator size="small" color={p.green} />
                                        ) : (
                                            <Ionicons name={it.icon} size={16} color={p.textMuted} />
                                        )}
                                    </RNView>
                                    <RNView style={styles.setupRowText}>
                                        <Text style={styles.setupRowTitle}>{it.title}</Text>
                                        <Text style={styles.setupRowBody}>{it.body}</Text>
                                    </RNView>
                                </RNView>
                            );
                        })}
                    </RNView>

                    <Pressable
                        style={[styles.createProfileButton, styles.setupButton, setupBusy && { opacity: 0.6 }]}
                        onPress={handleSetup}
                        disabled={setupBusy}
                    >
                        {setupBusy ? (
                            <ActivityIndicator color="#FFFFFF" size="small" />
                        ) : (
                            <>
                                <Ionicons name="scan" size={18} color="#FFFFFF" />
                                <Text style={styles.createProfileButtonText}>
                                    {t('profile.setupWith', { method: bioLabel })}
                                </Text>
                            </>
                        )}
                    </Pressable>

                    <Pressable
                        style={styles.recoverButton}
                        onPress={() => router.push('/recover-account' as never)}
                    >
                        <Ionicons name="key-outline" size={16} color={p.blue} />
                        <Text style={styles.recoverButtonText}>{t('profile.recoverExisting')}</Text>
                    </Pressable>
                </ScrollView>
            </RNView>
        );
    }

    const handleCopy = (label: string, value?: string) => {
        if (!value) return;
        Clipboard.setStringAsync(value);
        Alert.alert(t('common.copied'), t('profile.copiedToClipboard', { label }));
    };

    // The Privasys Account id is the IdP user id of the canonical account:
    // base64url of the 32-hex-char userId carried in the canonical DID
    // (did:web:privasys.id:users:<userId>). Same derivation as
    // ensurePrivasysSession, so what's shown here matches what the IdP,
    // recovery settings and support tooling call the account.
    const canonicalUserId = profile.canonicalDid?.split(':').pop() ?? '';
    const privasysAccountId = canonicalUserId
        ? btoa(canonicalUserId).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
        : '';

    return (
        <RNView style={styles.screen}>
            {/* Header */}
            <RNView style={[styles.header, { paddingTop: insets.top + 16 }]}>
                <Text style={styles.headerTitle}>Profile</Text>
            </RNView>

            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={styles.scrollContent}
                showsVerticalScrollIndicator={false}
            >
                {/* Avatar + Name */}
                <RNView style={styles.profileCard}>
                    <RNView style={styles.avatarContainer}>
                        {profile.avatarUri ? (
                            <Image
                                source={{ uri: profile.avatarUri }}
                                style={styles.avatarImage}
                                onError={(e) =>
                                    console.warn('[avatar] failed to load', profile.avatarUri, e.nativeEvent?.error)
                                }
                            />
                        ) : profile.displayName ? (
                            <RNView style={styles.avatar}>
                                <Text style={styles.avatarInitial}>
                                    {profile.displayName.charAt(0).toUpperCase()}
                                </Text>
                            </RNView>
                        ) : (
                            <RNView style={styles.avatar}>
                                <Ionicons name="person" size={36} color="#FFFFFF" />
                            </RNView>
                        )}
                    </RNView>
                    <Text style={styles.profileName}>
                        {profile.displayName || t('profile.defaultDisplayName')}
                    </Text>
                    {profile.email ? (
                        <Text style={styles.profileEmail}>{profile.email}</Text>
                    ) : null}
                </RNView>

                {/* DID */}
                <Text style={styles.sectionTitle}>{t('profile.sectionIdentity')}</Text>
                <Pressable
                    style={styles.didCard}
                    onPress={() => handleCopy(t('profile.canonicalDid'), profile.canonicalDid || profile.did)}
                >
                    <Ionicons name="finger-print" size={20} color={p.blue} />
                    <RNView style={{ flex: 1 }}>
                        <Text style={styles.didLabel}>{t('profile.canonicalDid')}</Text>
                        <Text style={styles.didText} numberOfLines={1}>
                            {profile.canonicalDid || t('profile.notGenerated')}
                        </Text>
                    </RNView>
                    <Ionicons name="copy-outline" size={18} color={p.textMuted} />
                </Pressable>
                <Pressable
                    style={styles.didCard}
                    onPress={() => handleCopy(t('profile.privasysAccount'), privasysAccountId)}
                >
                    <Ionicons name="person-circle-outline" size={20} color={p.blue} />
                    <RNView style={{ flex: 1 }}>
                        <Text style={styles.didLabel}>{t('profile.privasysAccount')}</Text>
                        <Text style={styles.didText} numberOfLines={1}>
                            {privasysAccountId || t('profile.notGenerated')}
                        </Text>
                    </RNView>
                    <Ionicons name="copy-outline" size={18} color={p.textMuted} />
                </Pressable>
                <Pressable
                    style={styles.didCard}
                    onPress={() => handleCopy(t('profile.deviceDid'), profile.did)}
                >
                    <Ionicons name="phone-portrait-outline" size={20} color={p.textSecondary} />
                    <RNView style={{ flex: 1 }}>
                        <Text style={styles.didLabel}>{t('profile.deviceDid')}</Text>
                        <Text style={styles.didText} numberOfLines={1}>
                            {profile.did || t('profile.notGenerated')}
                        </Text>
                    </RNView>
                    <Ionicons name="copy-outline" size={18} color={p.textMuted} />
                </Pressable>
                <Text style={styles.privacyNote}>{t('profile.privacyNote')}</Text>

                {/* Personal Data */}
                <Text style={styles.sectionTitle}>{t('profile.sectionPersonalData')}</Text>
                <Text style={styles.sectionDescription}>{t('profile.sectionPersonalDataHint')}</Text>

                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/personal-data' as never)}
                >
                    <RNView style={styles.sharingRow}>
                        <RNView style={styles.sharingIconContainer}>
                            <Ionicons name="document-text-outline" size={20} color={p.blue} />
                        </RNView>
                        <RNView style={{ flex: 1 }}>
                            <Text style={styles.sharingLabel}>{t('profile.manageAttributes')}</Text>
                            <Text style={styles.sharingDetail}>
                                {profile.attributes.length === 0
                                    ? t('profile.noAttributes')
                                    : t('profile.attributeCount', { count: profile.attributes.length })}
                            </Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                    </RNView>
                </Pressable>

                {/* Government-verified ID scan (highest assurance) */}
                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/kyc-capture' as never)}
                >
                    <RNView style={styles.sharingRow}>
                        <RNView style={styles.sharingIconContainer}>
                            <Ionicons name="shield-checkmark-outline" size={20} color={p.blue} />
                        </RNView>
                        <RNView style={{ flex: 1 }}>
                            <Text style={styles.sharingLabel}>{t('profile.idVerify')}</Text>
                            <Text style={styles.sharingDetail}>{t('profile.idVerifyHint')}</Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                    </RNView>
                </Pressable>

                {/* Import data (external IdPs) */}
                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/import' as never)}
                >
                    <RNView style={styles.sharingRow}>
                        <RNView style={styles.sharingIconContainer}>
                            <Ionicons name="cloud-download-outline" size={20} color={p.blue} />
                        </RNView>
                        <RNView style={{ flex: 1 }}>
                            <Text style={styles.sharingLabel}>{t('profile.importData')}</Text>
                            {/* Provider names are brands and stay as they are. */}
                            <Text style={styles.sharingDetail}>{t('profile.importDataHint')}</Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                    </RNView>
                </Pressable>

                {/* Export data */}
                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/export' as never)}
                >
                    <RNView style={styles.sharingRow}>
                        <RNView style={styles.sharingIconContainer}>
                            <Ionicons name="share-outline" size={20} color={p.blue} />
                        </RNView>
                        <RNView style={{ flex: 1 }}>
                            <Text style={styles.sharingLabel}>{t('profile.exportData')}</Text>
                            <Text style={styles.sharingDetail}>{t('profile.exportDataHint')}</Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                    </RNView>
                </Pressable>

                {/* Data Sharing — above recovery: reviewing what left the
                    wallet is the more frequent task. */}
                <Text style={styles.sectionTitle}>{t('profile.sectionDataSharing')}</Text>
                <Text style={styles.sectionDescription}>{t('profile.sectionDataSharingHint')}</Text>

                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/consent-history' as never)}
                >
                    <RNView style={styles.sharingRow}>
                        <RNView style={styles.sharingIconContainer}>
                            <Ionicons name="time-outline" size={20} color={p.blue} />
                        </RNView>
                        <RNView style={{ flex: 1 }}>
                            <Text style={styles.sharingLabel}>{t('profile.consentHistory')}</Text>
                            <Text style={styles.sharingDetail}>
                                {consentRecordCount === 0
                                    ? t('profile.noSharingEvents')
                                    : t('profile.eventCount', { count: consentRecordCount })}
                            </Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                    </RNView>
                </Pressable>

                {/* Account Recovery */}
                <Text style={styles.sectionTitle}>{t('profile.sectionRecovery')}</Text>
                <Text style={styles.sectionDescription}>{t('profile.sectionRecoveryHint')}</Text>

                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/account-recovery' as never)}
                >
                    <RNView style={styles.sharingRow}>
                        <RNView style={styles.sharingIconContainer}>
                            <Ionicons
                                name={recoveryPhraseSaved ? 'shield-checkmark-outline' : 'warning-outline'}
                                size={20}
                                color={recoveryPhraseSaved ? p.blue : '#F59E0B'}
                            />
                        </RNView>
                        <RNView style={{ flex: 1 }}>
                            <Text style={styles.sharingLabel}>{t('profile.recoverySettings')}</Text>
                            <Text
                                style={[
                                    styles.sharingDetail,
                                    !recoveryPhraseSaved && { color: '#B45309', fontWeight: '600' },
                                ]}
                            >
                                {recoveryPhraseSaved
                                    ? t('profile.recoveryConfigured')
                                    : t('home.savePhraseTitle')}
                            </Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                    </RNView>
                </Pressable>

                <Pressable
                    style={styles.sharingCard}
                    onPress={() => router.push('/recover-account' as never)}
                >
                    <RNView style={styles.sharingRow}>
                        <RNView style={styles.sharingIconContainer}>
                            <Ionicons name="key-outline" size={20} color={p.warnText} />
                        </RNView>
                        <RNView style={{ flex: 1 }}>
                            <Text style={styles.sharingLabel}>{t('profile.recoverAccount')}</Text>
                            <Text style={styles.sharingDetail}>{t('profile.recoverAccountHint')}</Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                    </RNView>
                </Pressable>

                {/* Profile metadata */}
                <Text style={styles.sectionTitle}>{t('profile.sectionDetails')}</Text>
                <RNView style={styles.metaCard}>
                    <RNView style={styles.metaRow}>
                        <Text style={styles.metaLabel}>{t('profile.created')}</Text>
                        <Text style={styles.metaValue}>
                            {t('time.onDate', { when: new Date(profile.createdAt * 1000) })}
                        </Text>
                    </RNView>
                    <RNView style={styles.metaRow}>
                        <Text style={styles.metaLabel}>{t('profile.lastUpdated')}</Text>
                        <Text style={styles.metaValue}>
                            {t('time.onDate', { when: new Date(profile.updatedAt * 1000) })}
                        </Text>
                    </RNView>
                    <RNView style={styles.metaRow}>
                        <Text style={styles.metaLabel}>{t('profile.dataAttributes')}</Text>
                        <Text style={styles.metaValue}>{profile.attributes.length}</Text>
                    </RNView>
                </RNView>

                {/* Danger Zone */}
                <RNView style={styles.dangerSection}>
                    <RNView style={styles.dangerDivider} />
                    <Text style={styles.dangerTitle}>{t('profile.dangerZone')}</Text>
                    <Text style={styles.dangerDescription}>{t('profile.dangerCredentials')}</Text>
                    <Pressable
                        style={styles.dangerButton}
                        onPress={() => router.push('/credentials' as never)}
                    >
                        <Ionicons name="key-outline" size={18} color={p.danger} />
                        <Text style={styles.dangerButtonText}>
                            {credentials.length > 0
                                ? t('profile.registeredCredentialsCount', { count: credentials.length })
                                : t('profile.registeredCredentials')}
                        </Text>
                    </Pressable>
                    <Text style={[styles.dangerDescription, { marginTop: 16 }]}>
                        {t('profile.dangerClearHint')}
                    </Text>
                    <Pressable
                        style={styles.dangerButton}
                        onPress={() => {
                            Alert.alert(
                                t('profile.clearAllData'),
                                t('profile.clearAllDataBody'),
                                [
                                    { text: t('common.cancel'), style: 'cancel' },
                                    {
                                        text: t('profile.clearEverything'),
                                        style: 'destructive',
                                        onPress: () => {
                                            for (const cred of credentials) {
                                                removeCredential(cred.credentialId);
                                            }
                                            for (const app of apps) {
                                                removeTrustedApp(app.rpId);
                                            }
                                            // The canonical meta-account lives in its own
                                            // slot OUTSIDE credentials[]; leaving it made
                                            // "Clear All Data" silently keep the old
                                            // account (and its possibly-dead credential)
                                            // for the next sign-in (2026-08-22).
                                            useAuthStore.getState().setPrivasysId(null);
                                            void clearSovereignLocalState();
                                            clearProfile();
                                            // Reset the setup ceremony so the
                                            // re-shown setup screen starts
                                            // clean (stale busy/done state
                                            // froze the button, 2026-08-22).
                                            setSetupBusy(false);
                                            setSetupDone(0);
                                        }
                                    }
                                ]
                            );
                        }}
                    >
                        <Ionicons name="trash-outline" size={18} color={p.danger} />
                        <Text style={styles.dangerButtonText}>{t('profile.clearAllData')}</Text>
                    </Pressable>
                </RNView>
            </ScrollView>
        </RNView>
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
    scrollView: { flex: 1 },
    scrollContent: { padding: 20, paddingBottom: 40 },
    emptyState: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        gap: 12,
        paddingHorizontal: 40
    },
    emptyTitle: { fontSize: 20, fontWeight: '600', color: p.textPrimary },
    emptyText: { fontSize: 15, color: p.textSecondary, textAlign: 'center', lineHeight: 22 },

    setupScroll: {
        flexGrow: 1,
        justifyContent: 'center',
        paddingHorizontal: 28,
        paddingVertical: 32,
        gap: 24
    },
    setupHeader: { alignItems: 'center', gap: 12 },
    setupTitle: { fontSize: 24, fontWeight: '700', color: p.textPrimary, letterSpacing: -0.3 },
    setupLede: {
        fontSize: 15,
        color: p.textSecondary,
        textAlign: 'center',
        lineHeight: 22,
        maxWidth: 340
    },
    setupCard: {
        backgroundColor: p.card,
        borderRadius: 16,
        borderWidth: 1,
        borderColor: p.border,
        padding: 18,
        gap: 16
    },
    setupRow: { flexDirection: 'row', alignItems: 'flex-start', gap: 14 },
    setupBubble: {
        width: 32,
        height: 32,
        borderRadius: 16,
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: p.cardAlt,
        borderWidth: 1,
        borderColor: p.border,
        marginTop: 1
    },
    setupBubbleDone: { backgroundColor: p.green, borderColor: p.green },
    setupRowText: { flex: 1, gap: 2 },
    setupRowTitle: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
    setupRowBody: { fontSize: 13.5, color: p.textSecondary, lineHeight: 19 },
    setupButton: {
        flexDirection: 'row',
        gap: 8,
        justifyContent: 'center',
        alignSelf: 'stretch',
        marginTop: 4
    },

    createProfileButton: {
        backgroundColor: p.blue,
        borderRadius: 12,
        paddingVertical: 14,
        paddingHorizontal: 32,
        marginTop: 8,
        alignItems: 'center' as const,
        minWidth: 180
    },
    createProfileButtonText: {
        color: '#FFFFFF',
        fontSize: 16,
        fontWeight: '600' as const
    },
    recoverButton: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 6,
        paddingVertical: 10,
        marginTop: 4,
    },
    recoverButtonText: {
        color: p.blue,
        fontSize: 14,
        fontWeight: '500',
    },

    profileCard: {
        alignItems: 'center',
        backgroundColor: p.card,
        borderRadius: 16,
        padding: 24,
        marginBottom: 24
    },
    avatarContainer: { marginBottom: 16 },
    avatar: {
        width: 80,
        height: 80,
        borderRadius: 40,
        backgroundColor: p.blue,
        alignItems: 'center',
        justifyContent: 'center'
    },
    avatarImage: {
        width: 80,
        height: 80,
        borderRadius: 40,
    },
    avatarInitial: {
        fontSize: 32,
        fontWeight: '700',
        color: '#FFFFFF'
    },
    profileName: { fontSize: 22, fontWeight: '700', color: p.textPrimary, marginBottom: 4 },
    profileEmail: { fontSize: 15, color: p.textSecondary },

    sectionTitle: {
        fontSize: 12,
        fontWeight: '700',
        color: p.textMuted,
        letterSpacing: 0.8,
        marginTop: 24,
        marginBottom: 8
    },
    sectionDescription: {
        fontSize: 13,
        color: p.textMuted,
        marginBottom: 12,
        lineHeight: 18
    },

    didCard: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 14,
        marginBottom: 8
    },
    didLabel: {
        fontSize: 11,
        fontWeight: '600',
        color: p.textMuted,
        textTransform: 'uppercase',
        letterSpacing: 0.5,
        marginBottom: 2
    },
    didText: {
        fontSize: 12,
        fontFamily: 'Inter',
        color: p.textSecondary,
        lineHeight: 18
    },
    privacyNote: {
        fontSize: 12,
        color: p.successText,
        marginTop: 4,
        marginBottom: 8,
        lineHeight: 16
    },

    exportButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        backgroundColor: p.card,
        borderRadius: 12,
        borderWidth: 1,
        borderColor: p.border,
        padding: 14,
        marginTop: 8,
    },
    exportButtonText: {
        fontSize: 15,
        fontWeight: '600',
        color: p.blue,
    },

    metaCard: {
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 16
    },
    metaRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        paddingVertical: 8,
        borderBottomWidth: 0.5,
        borderBottomColor: p.cardAlt
    },
    metaLabel: { fontSize: 14, color: p.textSecondary },
    metaValue: { fontSize: 14, fontWeight: '500', color: p.textPrimary },

    sharingCard: {
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 16,
        marginBottom: 8
    },
    sharingRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 14
    },
    sharingIconContainer: {
        width: 36,
        height: 36,
        borderRadius: 10,
        backgroundColor: p.cardAlt,
        alignItems: 'center',
        justifyContent: 'center'
    },
    sharingLabel: { fontSize: 15, fontWeight: '600', color: p.textPrimary, marginBottom: 2 },
    sharingDetail: { fontSize: 13, color: p.textSecondary },

    dangerSection: {
        marginTop: 40,
        alignItems: 'center',
        gap: 10,
        paddingBottom: 20,
    },
    dangerDivider: {
        width: 40,
        height: 1,
        backgroundColor: p.border,
        marginBottom: 4,
    },
    dangerTitle: {
        fontSize: 12,
        fontWeight: '600',
        color: p.textMuted,
        textTransform: 'uppercase',
        letterSpacing: 0.5,
    },
    dangerDescription: {
        fontSize: 13,
        color: p.textMuted,
        textAlign: 'center',
        lineHeight: 18,
        maxWidth: 280,
        marginBottom: 4,
    },
    dangerButton: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 8,
        borderRadius: 10,
        paddingVertical: 12,
        paddingHorizontal: 24,
        borderWidth: 1,
        borderColor: p.border,
    },
    dangerButtonText: { color: p.danger, fontSize: 14, fontWeight: '500' },
});
