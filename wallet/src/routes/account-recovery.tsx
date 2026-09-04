// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Account Recovery settings screen — configure recovery options.
 *
 * Sections:
 * - Recovery Codes: generate, manage, or deactivate backup codes
 * - Trusted Guardians: invite by email (deep link) or QR code scan
 * - Devices: view registered FIDO2 credentials
 * - Guardian Duties: invites/requests from others
 */

import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { useState, useEffect, useCallback, useMemo } from 'react';
import {
    StyleSheet,
    ScrollView,
    Pressable,
    View as RNView,
    TextInput,
    Alert,
    ActivityIndicator,
    RefreshControl,
    Share,
} from 'react-native';
import * as Clipboard from 'expo-clipboard';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { Text, usePalette, type Palette } from '@/components/Themed';
import {
    getRecoveryPhraseStatus,
    regenerateRecoveryPhrase,
    deleteRecoveryPhrase,
    listGuardians,
    inviteGuardianByEmail,
    addGuardianByQR,
    removeGuardian,
    listGuardianInvites,
    respondToGuardianInvite,
    listRecoveryRequests,
    approveRecovery,
    listDevices,
    revokeDevice,
    type GuardianInfo,
    type GuardianInvite,
    type RecoveryRequestInfo,
    type DeviceInfo,
} from '@/services/recovery-api';
import { ensurePrivasysSession, getPrivasysAccount } from '@/services/privasys-id';
import { establishPhraseWithBackup } from '@/services/sovereign';
import { useAuthStore } from '@/stores/auth';
import { profileName } from '@/services/attributes';
import { useProfileStore } from '@/stores/profile';

type InviteMethod = 'email' | 'qr';

export default function AccountRecoveryScreen() {
    const { t } = useTranslation();
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const profile = useProfileStore((s) => s.profile);
    const privasysId = useAuthStore((s) => s.privasysId);
    const credentialsList = useAuthStore((s) => s.credentials);
    const recoveryPhraseSaved = useAuthStore((s) => s.recoveryPhraseSaved);
    const setRecoveryPhraseSaved = useAuthStore((s) => s.setRecoveryPhraseSaved);

    // Wallet session token for management calls. The legacy `accessToken`
    // string is now `wallet:<sessionToken>` so that the same `Bearer ...`
    // header works for both new and legacy endpoints.
    const accessToken = privasysId?.sessionToken ? `wallet:${privasysId.sessionToken}` : '';
    const walletSessionToken = privasysId?.sessionToken ?? '';
    const userId = privasysId?.userId ?? '';
    // Credential ids this device holds for privasys.id (the canonical slot plus
    // any privasys.id entries in credentials[]), so the device list can mark
    // "This device" instead of an anonymous "Credential 3a4b…".
    const myCredentialIds = new Set<string>(
        [
            privasysId?.credentialId,
            ...credentialsList.filter((c) => c.rpId === 'privasys.id').map((c) => c.credentialId),
        ].filter((v): v is string => !!v),
    );

    const [refreshing, setRefreshing] = useState(false);
    const [loading, setLoading] = useState(true);
    const [signingIn, setSigningIn] = useState(false);

    // Recovery phrase
    const [phraseStatus, setPhraseStatus] = useState<{ has_phrase: boolean } | null>(null);
    const [newPhrase, setNewPhrase] = useState<string | null>(null);
    const [generatingPhrase, setGeneratingPhrase] = useState(false);

    // Guardians
    const [guardians, setGuardians] = useState<GuardianInfo[]>([]);
    const [guardianThreshold, setGuardianThreshold] = useState(0);
    const [guardianEmail, setGuardianEmail] = useState('');
    const [thresholdInput, setThresholdInput] = useState('1');
    const [showInviteForm, setShowInviteForm] = useState(false);
    const [inviteMethod, setInviteMethod] = useState<InviteMethod>('email');
    const [inviting, setInviting] = useState(false);

    // Devices
    const [devices, setDevices] = useState<DeviceInfo[]>([]);

    // Guardian duties
    const [pendingInvites, setPendingInvites] = useState<GuardianInvite[]>([]);
    const [recoveryRequests, setRecoveryRequests] = useState<RecoveryRequestInfo[]>([]);

    const acceptedGuardianCount = guardians.filter((g) => g.status === 'accepted').length;

    const loadData = useCallback(async () => {
        try {
            // Phrase status is public — fetch by user_id if known
            if (userId) {
                const ps = await getRecoveryPhraseStatus(userId).catch(() => null);
                if (ps) setPhraseStatus({ has_phrase: ps.has_phrase });
            }
            if (!accessToken) {
                setLoading(false);
                return;
            }
            const [guardiansRes, devicesRes, invitesRes, requestsRes] = await Promise.all([
                listGuardians(accessToken).catch(() => null),
                listDevices(accessToken).catch(() => null),
                listGuardianInvites(accessToken).catch(() => null),
                listRecoveryRequests(accessToken).catch(() => null),
            ]);
            if (guardiansRes) {
                setGuardians(guardiansRes.guardians || []);
                setGuardianThreshold(guardiansRes.threshold);
            }
            if (devicesRes) setDevices(devicesRes.devices || []);
            if (invitesRes) setPendingInvites(invitesRes.invites || []);
            if (requestsRes) setRecoveryRequests(requestsRes.requests || []);
        } catch (e) {
            console.warn('[account-recovery] load error:', e);
        } finally {
            setLoading(false);
        }
    }, [accessToken, userId]);

    useEffect(() => { loadData(); }, [loadData]);

    const onRefresh = useCallback(async () => {
        setRefreshing(true);
        await loadData();
        setRefreshing(false);
    }, [loadData]);

    // ── Privasys ID sign-in ──

    const handleSignIn = async () => {
        setSigningIn(true);
        try {
            const result = await ensurePrivasysSession(profileName(profile));
            // First registration: the server auto-mints a phrase and returns
            // it once, but we immediately supersede it with a CLIENT-minted
            // one whose plaintext never reaches the server — only its hash
            // is registered. The server-returned phrase is kept solely as
            // the fallback for an IdP that predates client-side generation.
            // Either way the sovereign backup is stored under whichever
            // phrase the user is shown.
            if (result.recoveryPhrase) {
                setRecoveryPhraseSaved(false);
                const r = await establishPhraseWithBackup(
                    result.sessionToken,
                    result.recoveryPhrase,
                    profile?.pairwiseSeed ?? null,
                );
                setNewPhrase(r.phrase);
                setPhraseStatus({ has_phrase: true });
                if (r.backupError) {
                    Alert.alert(
                        t('accountRecovery.backupIncompleteTitle'),
                        t('accountRecovery.backupIncompleteLater', { reason: r.backupError }),
                    );
                }
            }
            await loadData();
        } catch (e: any) {
            Alert.alert(t('accountRecovery.signInFailed'), e.message || String(e));
        } finally {
            setSigningIn(false);
        }
    };

    // ── Recovery phrase handlers ──

    const handleGeneratePhrase = async () => {
        Alert.alert(
            t('accountRecovery.generateTitle'),
            phraseStatus?.has_phrase
                ? t('accountRecovery.generateReplaceBody')
                : t('accountRecovery.generateNewBody'),
            [
                { text: t('common.cancel'), style: 'cancel' },
                {
                    text: t('accountRecovery.generate'),
                    onPress: async () => {
                        setGeneratingPhrase(true);
                        try {
                            // Refresh session if needed
                            const sess = await ensurePrivasysSession(profileName(profile));
                            // Client-side generation with legacy-IdP fallback,
                            // re-wrapping the sovereign backup under the new
                            // phrase in the same breath (the old phrase stops
                            // recovering the account the instant the new hash
                            // lands). Shared ceremony: establishPhraseWithBackup.
                            const r = await establishPhraseWithBackup(
                                sess.sessionToken,
                                null,
                                profile?.pairwiseSeed ?? null,
                            );
                            // A brand-new phrase is shown but not yet written
                            // down — un-confirm until the user taps "I've saved".
                            setRecoveryPhraseSaved(false);
                            setNewPhrase(r.phrase);
                            setPhraseStatus({ has_phrase: true });
                            if (r.backupError) {
                                Alert.alert(
                                    t('accountRecovery.backupIncompleteTitle'),
                                    t('accountRecovery.backupIncompleteAgain', { reason: r.backupError }),
                                );
                            }
                        } catch (e: any) {
                            Alert.alert(t('common.error'), e.message);
                        } finally {
                            setGeneratingPhrase(false);
                        }
                    },
                },
            ],
        );
    };

    const handleDeactivatePhrase = () => {
        Alert.alert(
            t('accountRecovery.deactivateTitle'),
            t('accountRecovery.deactivateBody'),
            [
                { text: t('accountRecovery.keepPhrase'), style: 'cancel' },
                {
                    text: t('accountRecovery.deactivateConfirm'),
                    style: 'destructive',
                    onPress: async () => {
                        try {
                            const sess = await ensurePrivasysSession(profileName(profile));
                            await deleteRecoveryPhrase(sess.sessionToken);
                            setRecoveryPhraseSaved(false);
                            setPhraseStatus({ has_phrase: false });
                            Alert.alert(t('accountRecovery.deactivated'), t('accountRecovery.deactivatedBody'));
                        } catch (e: any) {
                            Alert.alert(t('common.error'), e.message);
                        }
                    },
                },
            ],
        );
    };

    // ── Guardian handlers ──

    const handleInviteGuardianByEmail = async () => {
        if (!guardianEmail.trim()) return;
        const threshold = Math.max(1, parseInt(thresholdInput, 10) || 1);
        setInviting(true);
        try {
            const res = await inviteGuardianByEmail(accessToken, guardianEmail.trim(), threshold, profileName(profile) ?? '');
            setGuardianEmail('');
            setShowInviteForm(false);
            Alert.alert(
                t('accountRecovery.invited'),
                t('accountRecovery.invitedBody', { when: new Date(res.expires_at) })
            );
            await loadData();
        } catch (e: any) {
            Alert.alert(t('common.error'), e.message);
        } finally {
            setInviting(false);
        }
    };

    const handleAddGuardianByQR = async () => {
        // TODO: open camera, scan QR code, extract guardian_id from JSON.
        Alert.alert(t('accountRecovery.scanQrTitle'), t('accountRecovery.scanQrBody'));
    };

    const handleRemoveGuardian = (g: GuardianInfo) => {
        Alert.alert(
            t('accountRecovery.removeGuardianTitle'),
            t('accountRecovery.removeGuardianBody', { guardian: g.display_name || g.guardian_id }),
            [
            { text: t('common.cancel'), style: 'cancel' },
            {
                text: t('common.remove'),
                style: 'destructive',
                onPress: async () => {
                    try {
                        await removeGuardian(accessToken, g.guardian_id);
                        await loadData();
                    } catch (e: any) {
                        Alert.alert(t('common.error'), e.message);
                    }
                },
            },
        ]);
    };

    // ── Guardian duty handlers ──

    const handleRespondInvite = async (invite: GuardianInvite, accept: boolean) => {
        try {
            await respondToGuardianInvite(accessToken, invite.user_id, accept);
            Alert.alert(
                accept ? t('accountRecovery.accepted') : t('accountRecovery.declined'),
                accept ? t('accountRecovery.acceptedBody') : t('accountRecovery.declinedBody')
            );
            await loadData();
        } catch (e: any) {
            Alert.alert(t('common.error'), e.message);
        }
    };

    const handleApproveRecovery = (req: RecoveryRequestInfo, approved: boolean) => {
        Alert.alert(
            approved ? t('accountRecovery.approveRecovery') : t('accountRecovery.denyRecovery'),
            approved
                ? t('accountRecovery.approveRecoveryBody', { who: req.display_name || req.user_id })
                : t('accountRecovery.denyRecoveryBody', { who: req.display_name || req.user_id }),
            [
                { text: t('common.cancel'), style: 'cancel' },
                {
                    text: approved ? t('attestation.approve') : t('connect.deny'),
                    style: approved ? 'default' : 'destructive',
                    onPress: async () => {
                        try {
                            await approveRecovery(accessToken, req.request_id, approved);
                            Alert.alert(
                                t('common.done'),
                                approved ? t('accountRecovery.recoveryApproved') : t('accountRecovery.recoveryDenied')
                            );
                            await loadData();
                        } catch (e: any) {
                            Alert.alert(t('common.error'), e.message);
                        }
                    },
                },
            ],
        );
    };

    // ── Device handlers ──

    const handleRevokeDevice = (d: DeviceInfo) => {
        Alert.alert(
            t('accountRecovery.revokeDeviceTitle'),
            t('accountRecovery.revokeDeviceBody'),
            [
            { text: t('common.cancel'), style: 'cancel' },
            {
                text: t('history.revoke'),
                style: 'destructive',
                onPress: async () => {
                    try {
                        await revokeDevice(accessToken, d.credential_id);
                        await loadData();
                    } catch (e: any) {
                        Alert.alert(t('common.error'), e.message);
                    }
                },
            },
        ]);
    };

    const notConfigured = !accessToken;

    return (
        <RNView style={styles.screen}>
            {/* Header */}
            <RNView style={[styles.header, { paddingTop: insets.top + 8 }]}>
                <Pressable onPress={() => router.back()} hitSlop={12} style={styles.backButton}>
                    <Ionicons name="chevron-back" size={24} color="#FFFFFF" />
                </Pressable>
                <Text style={styles.headerTitle}>{t('profile.recoverySettings')}</Text>
                <RNView style={{ width: 32 }} />
            </RNView>

            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={[styles.scrollContent, { paddingBottom: insets.bottom + 32 }]}
                showsVerticalScrollIndicator={false}
                refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={p.blue} />}
            >
                {notConfigured && (
                    <RNView style={styles.card}>
                        <Text style={styles.fieldLabel}>{t('accountRecovery.lockedTitle')}</Text>
                        <Text style={styles.helperText}>{t('accountRecovery.lockedBody')}</Text>
                        {/* Outcome-named action: the biometric prompt appears as part
                            of unlocking, it is not the thing the user is asking for. */}
                        <Pressable
                            style={[styles.primaryButton, signingIn && { opacity: 0.6 }]}
                            onPress={handleSignIn}
                            disabled={signingIn}
                        >
                            {signingIn ? (
                                <ActivityIndicator color="#FFFFFF" size="small" />
                            ) : (
                                <Text style={styles.primaryButtonText}>{t('accountRecovery.unlock')}</Text>
                            )}
                        </Pressable>
                    </RNView>
                )}

                {/* ── Recovery Phrase ── */}
                <Text style={styles.sectionTitle}>{t('accountRecovery.sectionPhrase')}</Text>
                <Text style={styles.sectionDescription}>{t('accountRecovery.sectionPhraseHint')}</Text>

                {newPhrase ? (
                    <RNView style={styles.card}>
                        <Text style={[styles.fieldLabel, { marginBottom: 8 }]}>
                            {t('secureWallet.saveWords')}
                        </Text>
                        <RNView style={styles.codesGrid}>
                            {newPhrase.split(/\s+/).map((word, i) => (
                                <RNView key={i} style={styles.codeItem}>
                                    <Text style={styles.codeText}>{i + 1}. {word}</Text>
                                </RNView>
                            ))}
                        </RNView>
                        {/* Copy / export so the phrase can be printed. The
                            share sheet and clipboard are less private than
                            paper (clipboard managers, cloud share targets),
                            so the caution stays visible next to the actions. */}
                        <RNView style={{ flexDirection: 'row', gap: 10 }}>
                            <Pressable
                                style={[styles.secondaryButton, { flex: 1 }]}
                                onPress={async () => {
                                    await Clipboard.setStringAsync(newPhrase);
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
                                    void Share.share({ message: newPhrase });
                                }}
                            >
                                <Text style={styles.secondaryButtonText}>{t('secureWallet.sharePrint')}</Text>
                            </Pressable>
                        </RNView>
                        <Text style={styles.helperText}>{t('secureWallet.paperAdvice')}</Text>
                        <Pressable
                            style={styles.primaryButton}
                            onPress={() => {
                                // Confirmed: this is the one place the human tells
                                // us they wrote it down. Persist it so the nudge
                                // stops until the phrase is next (re)generated or
                                // invalidated.
                                setRecoveryPhraseSaved(true);
                                setNewPhrase(null);
                            }}
                        >
                            <Text style={styles.primaryButtonText}>{t('secureWallet.savedIt')}</Text>
                        </Pressable>
                    </RNView>
                ) : (
                    <RNView style={styles.card}>
                        {/* Honest, three-state status. has_phrase is only what
                            the SERVER knows; recoveryPhraseSaved is whether THIS
                            device confirmed the human wrote it down. After a
                            recovery the server deletes the phrase (has_phrase
                            false) and the flag is cleared, so both paths nudge. */}
                        {recoveryPhraseSaved && phraseStatus?.has_phrase ? (
                            <RNView style={styles.statusRow}>
                                <Ionicons name="checkmark-circle" size={20} color={p.green} />
                                <Text style={styles.statusText}>{t('accountRecovery.phraseSaved')}</Text>
                            </RNView>
                        ) : phraseStatus?.has_phrase ? (
                            <RNView style={styles.statusRow}>
                                <Ionicons name="warning-outline" size={20} color="#F59E0B" />
                                <Text style={styles.statusText}>{t('accountRecovery.phraseNotOnDevice')}</Text>
                            </RNView>
                        ) : (
                            <RNView style={styles.statusRow}>
                                <Ionicons name="alert-circle-outline" size={20} color="#F59E0B" />
                                <Text style={styles.statusText}>{t('accountRecovery.noPhrase')}</Text>
                            </RNView>
                        )}
                        {/* While signed out this rendered as a SECOND big blue
                            button (merely dimmed), indistinguishable from
                            "Sign in with biometrics" above. Two identical
                            primary actions. Signed out, sign-in is the one
                            true next step (it creates and shows the phrase on
                            first sign-in), so the generate button only exists
                            once a session does. */}
                        {!notConfigured && (
                            <Pressable
                                style={[styles.primaryButton, generatingPhrase && { opacity: 0.6 }]}
                                onPress={handleGeneratePhrase}
                                disabled={generatingPhrase}
                            >
                                {generatingPhrase ? (
                                    <ActivityIndicator color="#FFFFFF" size="small" />
                                ) : (
                                    <Text style={styles.primaryButtonText}>
                                        {phraseStatus?.has_phrase
                                            ? t('accountRecovery.regenerate')
                                            : t('accountRecovery.generateTitle')}
                                    </Text>
                                )}
                            </Pressable>
                        )}
                        {phraseStatus?.has_phrase && acceptedGuardianCount >= 1 && (
                            <Pressable
                                style={styles.secondaryButton}
                                onPress={handleDeactivatePhrase}
                            >
                                <Text style={[styles.secondaryButtonText, { color: p.danger, fontSize: 13 }]}>
                                    {t('accountRecovery.deactivateNotRecommended')}
                                </Text>
                            </Pressable>
                        )}
                    </RNView>
                )}

                {/* ── Trusted Guardians ── */}
                <Text style={styles.sectionTitle}>{t('accountRecovery.sectionGuardians')}</Text>
                <Text style={styles.sectionDescription}>{t('accountRecovery.sectionGuardiansHint')}</Text>

                {guardians.length > 0 && (
                    <RNView style={styles.card}>
                        <Text style={styles.fieldLabel}>
                            {t('accountRecovery.threshold', {
                                required: guardianThreshold,
                                total: guardians.length
                            })}
                        </Text>
                        {guardians.map((g) => (
                            <RNView key={g.guardian_id} style={styles.guardianRow}>
                                <Ionicons name="person-outline" size={18} color={p.textSecondary} />
                                <RNView style={{ flex: 1 }}>
                                    <Text style={styles.guardianName}>{g.display_name || g.guardian_id.substring(0, 8) + '…'}</Text>
                                    <Text style={[styles.guardianStatus, g.status === 'accepted' && { color: p.green }]}>
                                        {g.status}
                                    </Text>
                                </RNView>
                                <Pressable onPress={() => handleRemoveGuardian(g)} hitSlop={8}>
                                    <Ionicons name="close-circle-outline" size={20} color={p.textMuted} />
                                </Pressable>
                            </RNView>
                        ))}
                    </RNView>
                )}

                {showInviteForm ? (
                    <RNView style={styles.card}>
                        {/* Invite method selector */}
                        <RNView style={styles.methodSelector}>
                            <Pressable
                                style={[styles.methodOption, inviteMethod === 'email' && styles.methodOptionActive]}
                                onPress={() => setInviteMethod('email')}
                            >
                                <Ionicons name="mail-outline" size={16} color={inviteMethod === 'email' ? p.blue : p.textMuted} />
                                <Text style={[styles.methodText, inviteMethod === 'email' && styles.methodTextActive]}>
                                    {t('accountRecovery.methodEmail')}
                                </Text>
                            </Pressable>
                            <Pressable
                                style={[styles.methodOption, inviteMethod === 'qr' && styles.methodOptionActive]}
                                onPress={() => setInviteMethod('qr')}
                            >
                                <Ionicons name="qr-code-outline" size={16} color={inviteMethod === 'qr' ? p.blue : p.textMuted} />
                                <Text style={[styles.methodText, inviteMethod === 'qr' && styles.methodTextActive]}>
                                    {t('accountRecovery.methodQr')}
                                </Text>
                            </Pressable>
                        </RNView>

                        {inviteMethod === 'email' ? (
                            <>
                                <Text style={styles.fieldLabel}>{t('accountRecovery.guardianEmail')}</Text>
                                <TextInput
                                    style={styles.input}
                                    value={guardianEmail}
                                    onChangeText={setGuardianEmail}
                                    placeholder={t('accountRecovery.guardianEmailPlaceholder')}
                                    placeholderTextColor={p.textMuted}
                                    keyboardType="email-address"
                                    autoCapitalize="none"
                                    autoFocus
                                />
                                <Text style={[styles.fieldLabel, { marginTop: 8 }]}>{t('accountRecovery.approvalThreshold')}</Text>
                                <TextInput
                                    style={styles.input}
                                    value={thresholdInput}
                                    onChangeText={setThresholdInput}
                                    placeholder="1"
                                    placeholderTextColor={p.textMuted}
                                    keyboardType="number-pad"
                                    maxLength={2}
                                />
                                <Text style={styles.helperText}>{t('accountRecovery.inviteEmailHint')}</Text>
                                <RNView style={styles.formActions}>
                                    <Pressable onPress={() => setShowInviteForm(false)}>
                                        <Text style={styles.cancelText}>{t('common.cancel')}</Text>
                                    </Pressable>
                                    <Pressable
                                        style={[styles.primaryButton, { flex: 0, paddingHorizontal: 24 }, (inviting || !guardianEmail.trim()) && { opacity: 0.6 }]}
                                        onPress={handleInviteGuardianByEmail}
                                        disabled={inviting || !guardianEmail.trim()}
                                    >
                                        {inviting ? (
                                            <ActivityIndicator color="#FFFFFF" size="small" />
                                        ) : (
                                            <Text style={styles.primaryButtonText}>{t('accountRecovery.sendInvite')}</Text>
                                        )}
                                    </Pressable>
                                </RNView>
                            </>
                        ) : (
                            <>
                                <Text style={styles.helperText}>{t('accountRecovery.inviteQrHint')}</Text>
                                <RNView style={styles.formActions}>
                                    <Pressable onPress={() => setShowInviteForm(false)}>
                                        <Text style={styles.cancelText}>{t('common.cancel')}</Text>
                                    </Pressable>
                                    <Pressable
                                        style={[styles.primaryButton, { flex: 0, paddingHorizontal: 24 }]}
                                        onPress={handleAddGuardianByQR}
                                    >
                                        <Ionicons name="camera-outline" size={18} color="#FFFFFF" />
                                        <Text style={[styles.primaryButtonText, { marginLeft: 6 }]}>
                                            {t('accountRecovery.openScanner')}
                                        </Text>
                                    </Pressable>
                                </RNView>
                            </>
                        )}
                    </RNView>
                ) : (
                    <Pressable
                        style={[styles.outlineButton, notConfigured && { opacity: 0.4 }]}
                        onPress={() => setShowInviteForm(true)}
                        disabled={notConfigured}
                    >
                        <Ionicons name="person-add-outline" size={18} color={p.blue} />
                        <Text style={styles.outlineButtonText}>{t('accountRecovery.addGuardian')}</Text>
                    </Pressable>
                )}

                {/* ── Devices ── */}
                <Text style={styles.sectionTitle}>{t('accountRecovery.sectionDevices')}</Text>
                <Text style={styles.sectionDescription}>{t('accountRecovery.sectionDevicesHint')}</Text>

                {devices.length === 0 ? (
                    <RNView style={styles.emptyCard}>
                        <Ionicons name="phone-portrait-outline" size={28} color={p.textMuted} />
                        <Text style={styles.emptyText}>{t('accountRecovery.noDevices')}</Text>
                    </RNView>
                ) : (
                    <RNView style={styles.card}>
                        {devices.map((d, i) => {
                            const isThisDevice = myCredentialIds.has(d.credential_id);
                            return (
                            <RNView
                                key={d.credential_id}
                                style={[styles.deviceRow, i === devices.length - 1 && styles.deviceRowLast]}
                            >
                                <Ionicons name="phone-portrait-outline" size={18} color={isThisDevice ? p.green : p.textSecondary} />
                                <RNView style={{ flex: 1 }}>
                                    <RNView style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
                                        <Text style={styles.deviceLabel}>
                                            {isThisDevice
                                                ? t('accountRecovery.thisDevice')
                                                : t('accountRecovery.credentialLabel', {
                                                    id: d.credential_id.substring(0, 8)
                                                })}
                                        </Text>
                                        {isThisDevice && (
                                            <RNView style={styles.thisDeviceBadge}>
                                                <Text style={styles.thisDeviceBadgeText}>{t('accountRecovery.current')}</Text>
                                            </RNView>
                                        )}
                                    </RNView>
                                    <Text style={styles.deviceDetail}>
                                        {t('accountRecovery.deviceMeta', {
                                            count: d.sign_count,
                                            when: new Date(d.created_at)
                                        })}
                                    </Text>
                                </RNView>
                                {/* Never let the user revoke the device they are on — it would
                                    lock them out. Other devices stay revocable. */}
                                {!isThisDevice && (
                                    <Pressable onPress={() => handleRevokeDevice(d)} hitSlop={8}>
                                        <Ionicons name="trash-outline" size={18} color={p.danger} />
                                    </Pressable>
                                )}
                            </RNView>
                            );
                        })}
                    </RNView>
                )}

                {/* ── Guardian Duties ── */}
                {(pendingInvites.length > 0 || recoveryRequests.length > 0) && (
                    <>
                        <Text style={styles.sectionTitle}>{t('accountRecovery.sectionDuties')}</Text>
                        <Text style={styles.sectionDescription}>{t('accountRecovery.sectionDutiesHint')}</Text>

                        {pendingInvites.map((inv) => (
                            <RNView key={inv.user_id} style={styles.card}>
                                <Text style={styles.dutyTitle}>{t('accountRecovery.dutyInvitation')}</Text>
                                <Text style={styles.dutyDescription}>
                                    {t('accountRecovery.dutyInvitationBody', {
                                        who: inv.display_name || inv.user_id
                                    })}
                                </Text>
                                <RNView style={styles.formActions}>
                                    <Pressable
                                        style={[styles.outlineButton, { flex: 0, borderColor: p.danger }]}
                                        onPress={() => handleRespondInvite(inv, false)}
                                    >
                                        <Text style={[styles.outlineButtonText, { color: p.danger }]}>
                                            {t('accountRecovery.decline')}
                                        </Text>
                                    </Pressable>
                                    <Pressable
                                        style={[styles.primaryButton, { flex: 0, paddingHorizontal: 24 }]}
                                        onPress={() => handleRespondInvite(inv, true)}
                                    >
                                        <Text style={styles.primaryButtonText}>{t('accountRecovery.accept')}</Text>
                                    </Pressable>
                                </RNView>
                            </RNView>
                        ))}

                        {recoveryRequests.map((req) => (
                            <RNView key={req.request_id} style={styles.card}>
                                <Text style={styles.dutyTitle}>{t('accountRecovery.dutyRecovery')}</Text>
                                <Text style={styles.dutyDescription}>
                                    {t('accountRecovery.dutyRecoveryBody', {
                                        who: req.display_name || req.user_id
                                    })}
                                </Text>
                                <RNView style={styles.formActions}>
                                    <Pressable
                                        style={[styles.outlineButton, { flex: 0, borderColor: p.danger }]}
                                        onPress={() => handleApproveRecovery(req, false)}
                                    >
                                        <Text style={[styles.outlineButtonText, { color: p.danger }]}>
                                            {t('connect.deny')}
                                        </Text>
                                    </Pressable>
                                    <Pressable
                                        style={[styles.primaryButton, { flex: 0, paddingHorizontal: 24 }]}
                                        onPress={() => handleApproveRecovery(req, true)}
                                    >
                                        <Text style={styles.primaryButtonText}>{t('attestation.approve')}</Text>
                                    </Pressable>
                                </RNView>
                            </RNView>
                        ))}
                    </>
                )}

                <RNView style={{ height: 40 }} />
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

    sectionTitle: {
        fontSize: 12,
        fontWeight: '700',
        color: p.textMuted,
        letterSpacing: 0.8,
        marginTop: 24,
        marginBottom: 6,
    },
    sectionDescription: {
        fontSize: 13,
        color: p.textMuted,
        marginBottom: 12,
        lineHeight: 18,
    },

    card: {
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 16,
        marginBottom: 8,
    },
    infoCard: {
        flexDirection: 'row',
        alignItems: 'flex-start',
        gap: 10,
        backgroundColor: p.warnBg,
        borderRadius: 12,
        padding: 14,
        marginBottom: 8,
    },
    infoText: {
        flex: 1,
        fontSize: 13,
        color: p.warnText,
        lineHeight: 18,
    },

    fieldLabel: {
        fontSize: 12,
        fontWeight: '600',
        color: p.textMuted,
        marginBottom: 6,
        textTransform: 'uppercase',
        letterSpacing: 0.3,
    },
    helperText: {
        fontSize: 13,
        color: p.textMuted,
        lineHeight: 18,
        marginBottom: 12,
    },
    input: {
        backgroundColor: p.cardAlt,
        borderRadius: 10,
        paddingHorizontal: 14,
        paddingVertical: 12,
        fontSize: 16,
        color: p.textPrimary,
        marginBottom: 12,
    },

    primaryButton: {
        backgroundColor: p.blue,
        borderRadius: 10,
        paddingVertical: 12,
        alignItems: 'center' as const,
        flexDirection: 'row',
        justifyContent: 'center',
    },
    primaryButtonText: {
        color: '#FFFFFF',
        fontSize: 15,
        fontWeight: '600',
    },
    secondaryButton: {
        alignItems: 'center' as const,
        paddingVertical: 10,
        marginTop: 8,
    },
    secondaryButtonText: {
        color: p.blue,
        fontSize: 14,
        fontWeight: '500',
    },
    outlineButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        borderWidth: 1,
        borderColor: p.blue,
        borderRadius: 10,
        paddingVertical: 12,
        paddingHorizontal: 16,
    },
    outlineButtonText: {
        color: p.blue,
        fontSize: 15,
        fontWeight: '600',
    },
    cancelText: {
        color: p.textMuted,
        fontSize: 14,
        fontWeight: '500',
    },
    formActions: {
        flexDirection: 'row',
        justifyContent: 'flex-end',
        alignItems: 'center',
        gap: 12,
        marginTop: 8,
    },

    // Method selector (email / QR)
    methodSelector: {
        flexDirection: 'row',
        gap: 8,
        marginBottom: 16,
    },
    methodOption: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        borderWidth: 1,
        borderColor: p.border,
        borderRadius: 8,
        paddingVertical: 10,
    },
    methodOptionActive: {
        borderColor: p.blue,
        backgroundColor: p.cardAlt,
    },
    methodText: {
        fontSize: 14,
        fontWeight: '500',
        color: p.textMuted,
    },
    methodTextActive: {
        color: p.blue,
    },

    // Status row (codes, etc.)
    statusRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        marginBottom: 12,
    },
    statusText: {
        flex: 1,
        fontSize: 14,
        color: p.textPrimary,
        fontWeight: '500',
    },

    // Recovery codes grid
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

    // Guardian row
    guardianRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        paddingVertical: 10,
        borderBottomWidth: 0.5,
        borderBottomColor: p.border,
    },
    guardianName: {
        fontSize: 14,
        color: p.textPrimary,
        fontWeight: '500',
    },
    guardianStatus: {
        fontSize: 12,
        color: p.textMuted,
        textTransform: 'capitalize',
    },

    // Device row
    deviceRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        paddingVertical: 10,
        borderBottomWidth: 0.5,
        borderBottomColor: p.border,
    },
    deviceRowLast: {
        borderBottomWidth: 0,
    },
    deviceLabel: {
        fontSize: 14,
        color: p.textPrimary,
        fontWeight: '500',
    },
    thisDeviceBadge: {
        backgroundColor: p.green,
        borderRadius: 6,
        paddingHorizontal: 6,
        paddingVertical: 1,
    },
    thisDeviceBadgeText: {
        color: '#FFFFFF',
        fontSize: 10,
        fontWeight: '700',
    },
    deviceDetail: {
        fontSize: 12,
        color: p.textMuted,
    },

    // Guardian duties
    dutyTitle: {
        fontSize: 15,
        fontWeight: '600',
        color: p.textPrimary,
        marginBottom: 4,
    },
    dutyDescription: {
        fontSize: 13,
        color: p.textSecondary,
        lineHeight: 18,
        marginBottom: 8,
    },

    // Empty state
    emptyCard: {
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 24,
        gap: 8,
    },
    emptyText: {
        fontSize: 14,
        color: p.textMuted,
    },
});
