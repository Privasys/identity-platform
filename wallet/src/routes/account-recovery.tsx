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
import { useState, useEffect, useCallback } from 'react';
import {
    StyleSheet,
    ScrollView,
    Pressable,
    View as RNView,
    TextInput,
    Alert,
    ActivityIndicator,
    RefreshControl,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
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
import { ensurePrivasysSession, getPrivasysAccount } from '@/services/privasys-account';
import { useAuthStore } from '@/stores/auth';
import { useProfileStore } from '@/stores/profile';

type InviteMethod = 'email' | 'qr';

export default function AccountRecoveryScreen() {
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const profile = useProfileStore((s) => s.profile);
    const privasysId = useAuthStore((s) => s.privasysId);

    // Wallet session token for management calls. The legacy `accessToken`
    // string is now `wallet:<sessionToken>` so that the same `Bearer ...`
    // header works for both new and legacy endpoints.
    const accessToken = privasysId?.sessionToken ? `wallet:${privasysId.sessionToken}` : '';
    const walletSessionToken = privasysId?.sessionToken ?? '';
    const userId = privasysId?.userId ?? '';

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
            const result = await ensurePrivasysSession(profile?.displayName);
            // First registration returns the recovery phrase exactly once
            if (result.recoveryPhrase) {
                setNewPhrase(result.recoveryPhrase);
                setPhraseStatus({ has_phrase: true });
            }
            await loadData();
        } catch (e: any) {
            Alert.alert('Sign-in failed', e.message || String(e));
        } finally {
            setSigningIn(false);
        }
    };

    // ── Recovery phrase handlers ──

    const handleGeneratePhrase = async () => {
        Alert.alert(
            'Generate Recovery Phrase',
            phraseStatus?.has_phrase
                ? 'This will replace your existing 24-word recovery phrase. The old phrase will no longer work.'
                : 'Generate a new 24-word recovery phrase. Write it down and store it in a safe place — it will only be shown once.',
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Generate',
                    onPress: async () => {
                        setGeneratingPhrase(true);
                        try {
                            // Refresh session if needed
                            const sess = await ensurePrivasysSession(profile?.displayName);
                            const res = await regenerateRecoveryPhrase(sess.sessionToken);
                            setNewPhrase(res.phrase);
                            setPhraseStatus({ has_phrase: true });
                        } catch (e: any) {
                            Alert.alert('Error', e.message);
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
            'Deactivate Recovery Phrase',
            'WARNING: Without a recovery phrase, your guardians could collude to take over your account. ' +
            'Only deactivate if you fully trust all your guardians.\n\n' +
            'Are you sure you want to delete your recovery phrase?',
            [
                { text: 'Keep Phrase', style: 'cancel' },
                {
                    text: 'I Understand, Deactivate',
                    style: 'destructive',
                    onPress: async () => {
                        try {
                            const sess = await ensurePrivasysSession(profile?.displayName);
                            await deleteRecoveryPhrase(sess.sessionToken);
                            setPhraseStatus({ has_phrase: false });
                            Alert.alert('Deactivated', 'Recovery phrase deleted. You can regenerate one at any time.');
                        } catch (e: any) {
                            Alert.alert('Error', e.message);
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
            const res = await inviteGuardianByEmail(accessToken, guardianEmail.trim(), threshold, profile?.displayName ?? '');
            setGuardianEmail('');
            setShowInviteForm(false);
            Alert.alert('Invited', `Guardian invitation email sent. Expires ${new Date(res.expires_at).toLocaleDateString()}.`);
            await loadData();
        } catch (e: any) {
            Alert.alert('Error', e.message);
        } finally {
            setInviting(false);
        }
    };

    const handleAddGuardianByQR = async () => {
        // TODO: open camera, scan QR code, extract guardian_id from JSON.
        Alert.alert('Scan QR Code', 'Camera QR scanner will be available in a future update.');
    };

    const handleRemoveGuardian = (g: GuardianInfo) => {
        Alert.alert('Remove Guardian', `Remove ${g.display_name || g.guardian_id} as a guardian?`, [
            { text: 'Cancel', style: 'cancel' },
            {
                text: 'Remove',
                style: 'destructive',
                onPress: async () => {
                    try {
                        await removeGuardian(accessToken, g.guardian_id);
                        await loadData();
                    } catch (e: any) {
                        Alert.alert('Error', e.message);
                    }
                },
            },
        ]);
    };

    // ── Guardian duty handlers ──

    const handleRespondInvite = async (invite: GuardianInvite, accept: boolean) => {
        try {
            await respondToGuardianInvite(accessToken, invite.user_id, accept);
            Alert.alert(accept ? 'Accepted' : 'Declined', accept ? 'You are now a guardian.' : 'Invitation declined.');
            await loadData();
        } catch (e: any) {
            Alert.alert('Error', e.message);
        }
    };

    const handleApproveRecovery = (req: RecoveryRequestInfo, approved: boolean) => {
        Alert.alert(
            approved ? 'Approve Recovery' : 'Deny Recovery',
            `${approved ? 'Approve' : 'Deny'} the recovery request from ${req.display_name || req.user_id}?`,
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: approved ? 'Approve' : 'Deny',
                    style: approved ? 'default' : 'destructive',
                    onPress: async () => {
                        try {
                            await approveRecovery(accessToken, req.request_id, approved);
                            Alert.alert('Done', approved ? 'Recovery approved.' : 'Recovery denied.');
                            await loadData();
                        } catch (e: any) {
                            Alert.alert('Error', e.message);
                        }
                    },
                },
            ],
        );
    };

    // ── Device handlers ──

    const handleRevokeDevice = (d: DeviceInfo) => {
        Alert.alert('Revoke Device', 'This will remove the credential. The device will no longer be able to authenticate.', [
            { text: 'Cancel', style: 'cancel' },
            {
                text: 'Revoke',
                style: 'destructive',
                onPress: async () => {
                    try {
                        await revokeDevice(accessToken, d.credential_id);
                        await loadData();
                    } catch (e: any) {
                        Alert.alert('Error', e.message);
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
                <Text style={styles.headerTitle}>Recovery Settings</Text>
                <RNView style={{ width: 32 }} />
            </RNView>

            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={styles.scrollContent}
                showsVerticalScrollIndicator={false}
                refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#00BCF2" />}
            >
                {notConfigured && (
                    <RNView style={styles.card}>
                        <Text style={styles.fieldLabel}>Sign in to Privasys ID</Text>
                        <Text style={styles.helperText}>
                            Recovery management requires a wallet session. Sign in once with your biometrics
                            to manage your recovery phrase, guardians and registered devices.
                        </Text>
                        <Pressable
                            style={[styles.primaryButton, signingIn && { opacity: 0.6 }]}
                            onPress={handleSignIn}
                            disabled={signingIn}
                        >
                            {signingIn ? (
                                <ActivityIndicator color="#FFFFFF" size="small" />
                            ) : (
                                <Text style={styles.primaryButtonText}>Sign in with biometrics</Text>
                            )}
                        </Pressable>
                    </RNView>
                )}

                {/* ── Recovery Phrase ── */}
                <Text style={styles.sectionTitle}>RECOVERY PHRASE</Text>
                <Text style={styles.sectionDescription}>
                    A 24-word phrase to regain access if you lose your device. Write it down on paper
                    and store it somewhere safe — it will only be shown once.
                </Text>

                {newPhrase ? (
                    <RNView style={styles.card}>
                        <Text style={[styles.fieldLabel, { marginBottom: 8 }]}>
                            Save these 24 words in order — they won't be shown again
                        </Text>
                        <RNView style={styles.codesGrid}>
                            {newPhrase.split(/\s+/).map((word, i) => (
                                <RNView key={i} style={styles.codeItem}>
                                    <Text style={styles.codeText}>{i + 1}. {word}</Text>
                                </RNView>
                            ))}
                        </RNView>
                        <Pressable
                            style={styles.secondaryButton}
                            onPress={() => setNewPhrase(null)}
                        >
                            <Text style={styles.secondaryButtonText}>I've saved my phrase</Text>
                        </Pressable>
                    </RNView>
                ) : (
                    <RNView style={styles.card}>
                        {phraseStatus ? (
                            <RNView style={styles.statusRow}>
                                <Ionicons
                                    name={phraseStatus.has_phrase ? 'checkmark-circle' : 'alert-circle-outline'}
                                    size={20}
                                    color={phraseStatus.has_phrase ? '#34E89E' : '#F59E0B'}
                                />
                                <Text style={styles.statusText}>
                                    {phraseStatus.has_phrase ? 'Recovery phrase configured' : 'No recovery phrase configured'}
                                </Text>
                            </RNView>
                        ) : (
                            <RNView style={styles.statusRow}>
                                <Ionicons name="alert-circle-outline" size={20} color="#94A3B8" />
                                <Text style={styles.statusText}>Recovery phrase not set up</Text>
                            </RNView>
                        )}
                        <Pressable
                            style={[styles.primaryButton, (generatingPhrase || notConfigured) && { opacity: 0.6 }]}
                            onPress={handleGeneratePhrase}
                            disabled={generatingPhrase || notConfigured}
                        >
                            {generatingPhrase ? (
                                <ActivityIndicator color="#FFFFFF" size="small" />
                            ) : (
                                <Text style={styles.primaryButtonText}>
                                    {phraseStatus?.has_phrase ? 'Regenerate Phrase' : 'Generate Recovery Phrase'}
                                </Text>
                            )}
                        </Pressable>
                        {phraseStatus?.has_phrase && acceptedGuardianCount >= 1 && (
                            <Pressable
                                style={styles.secondaryButton}
                                onPress={handleDeactivatePhrase}
                            >
                                <Text style={[styles.secondaryButtonText, { color: '#DC2626', fontSize: 13 }]}>Deactivate Phrase (not recommended)</Text>
                            </Pressable>
                        )}
                    </RNView>
                )}

                {/* ── Trusted Guardians ── */}
                <Text style={styles.sectionTitle}>TRUSTED GUARDIANS</Text>
                <Text style={styles.sectionDescription}>
                    Nominate trusted contacts who can approve your account recovery. Invite them by email or scan their QR code.
                </Text>

                {guardians.length > 0 && (
                    <RNView style={styles.card}>
                        <Text style={styles.fieldLabel}>
                            Threshold: {guardianThreshold} of {guardians.length} required
                        </Text>
                        {guardians.map((g) => (
                            <RNView key={g.guardian_id} style={styles.guardianRow}>
                                <Ionicons name="person-outline" size={18} color="#64748B" />
                                <RNView style={{ flex: 1 }}>
                                    <Text style={styles.guardianName}>{g.display_name || g.guardian_id.substring(0, 8) + '…'}</Text>
                                    <Text style={[styles.guardianStatus, g.status === 'accepted' && { color: '#34E89E' }]}>
                                        {g.status}
                                    </Text>
                                </RNView>
                                <Pressable onPress={() => handleRemoveGuardian(g)} hitSlop={8}>
                                    <Ionicons name="close-circle-outline" size={20} color="#94A3B8" />
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
                                <Ionicons name="mail-outline" size={16} color={inviteMethod === 'email' ? '#00BCF2' : '#94A3B8'} />
                                <Text style={[styles.methodText, inviteMethod === 'email' && styles.methodTextActive]}>Email</Text>
                            </Pressable>
                            <Pressable
                                style={[styles.methodOption, inviteMethod === 'qr' && styles.methodOptionActive]}
                                onPress={() => setInviteMethod('qr')}
                            >
                                <Ionicons name="qr-code-outline" size={16} color={inviteMethod === 'qr' ? '#00BCF2' : '#94A3B8'} />
                                <Text style={[styles.methodText, inviteMethod === 'qr' && styles.methodTextActive]}>Scan QR</Text>
                            </Pressable>
                        </RNView>

                        {inviteMethod === 'email' ? (
                            <>
                                <Text style={styles.fieldLabel}>Guardian's email</Text>
                                <TextInput
                                    style={styles.input}
                                    value={guardianEmail}
                                    onChangeText={setGuardianEmail}
                                    placeholder="guardian@example.com"
                                    placeholderTextColor="#94A3B8"
                                    keyboardType="email-address"
                                    autoCapitalize="none"
                                    autoFocus
                                />
                                <Text style={[styles.fieldLabel, { marginTop: 8 }]}>Approval threshold (k)</Text>
                                <TextInput
                                    style={styles.input}
                                    value={thresholdInput}
                                    onChangeText={setThresholdInput}
                                    placeholder="1"
                                    placeholderTextColor="#94A3B8"
                                    keyboardType="number-pad"
                                    maxLength={2}
                                />
                                <Text style={styles.helperText}>
                                    An invitation email with a link will be sent. They don't need the app yet.
                                </Text>
                                <RNView style={styles.formActions}>
                                    <Pressable onPress={() => setShowInviteForm(false)}>
                                        <Text style={styles.cancelText}>Cancel</Text>
                                    </Pressable>
                                    <Pressable
                                        style={[styles.primaryButton, { flex: 0, paddingHorizontal: 24 }, (inviting || !guardianEmail.trim()) && { opacity: 0.6 }]}
                                        onPress={handleInviteGuardianByEmail}
                                        disabled={inviting || !guardianEmail.trim()}
                                    >
                                        {inviting ? (
                                            <ActivityIndicator color="#FFFFFF" size="small" />
                                        ) : (
                                            <Text style={styles.primaryButtonText}>Send Invite</Text>
                                        )}
                                    </Pressable>
                                </RNView>
                            </>
                        ) : (
                            <>
                                <Text style={styles.helperText}>
                                    Ask your guardian to open their Privasys Wallet and show their Guardian QR code, then scan it with your camera.
                                </Text>
                                <RNView style={styles.formActions}>
                                    <Pressable onPress={() => setShowInviteForm(false)}>
                                        <Text style={styles.cancelText}>Cancel</Text>
                                    </Pressable>
                                    <Pressable
                                        style={[styles.primaryButton, { flex: 0, paddingHorizontal: 24 }]}
                                        onPress={handleAddGuardianByQR}
                                    >
                                        <Ionicons name="camera-outline" size={18} color="#FFFFFF" />
                                        <Text style={[styles.primaryButtonText, { marginLeft: 6 }]}>Open Scanner</Text>
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
                        <Ionicons name="person-add-outline" size={18} color="#00BCF2" />
                        <Text style={styles.outlineButtonText}>Add Guardian</Text>
                    </Pressable>
                )}

                {/* ── Devices ── */}
                <Text style={styles.sectionTitle}>REGISTERED DEVICES</Text>
                <Text style={styles.sectionDescription}>
                    FIDO2 credentials registered on the Privasys ID server for your account.
                </Text>

                {devices.length === 0 ? (
                    <RNView style={styles.emptyCard}>
                        <Ionicons name="phone-portrait-outline" size={28} color="#C7C7CC" />
                        <Text style={styles.emptyText}>No registered devices</Text>
                    </RNView>
                ) : (
                    <RNView style={styles.card}>
                        {devices.map((d) => (
                            <RNView key={d.credential_id} style={styles.deviceRow}>
                                <Ionicons name="phone-portrait-outline" size={18} color="#64748B" />
                                <RNView style={{ flex: 1 }}>
                                    <Text style={styles.deviceLabel}>
                                        Credential {d.credential_id.substring(0, 8)}…
                                    </Text>
                                    <Text style={styles.deviceDetail}>
                                        Sign count: {d.sign_count} · Registered: {new Date(d.created_at).toLocaleDateString()}
                                    </Text>
                                </RNView>
                                <Pressable onPress={() => handleRevokeDevice(d)} hitSlop={8}>
                                    <Ionicons name="trash-outline" size={18} color="#DC2626" />
                                </Pressable>
                            </RNView>
                        ))}
                    </RNView>
                )}

                {/* ── Guardian Duties ── */}
                {(pendingInvites.length > 0 || recoveryRequests.length > 0) && (
                    <>
                        <Text style={styles.sectionTitle}>GUARDIAN DUTIES</Text>
                        <Text style={styles.sectionDescription}>
                            Actions requested of you as a trusted guardian.
                        </Text>

                        {pendingInvites.map((inv) => (
                            <RNView key={inv.user_id} style={styles.card}>
                                <Text style={styles.dutyTitle}>Guardian Invitation</Text>
                                <Text style={styles.dutyDescription}>
                                    {inv.display_name || inv.user_id} wants you as a recovery guardian.
                                </Text>
                                <RNView style={styles.formActions}>
                                    <Pressable
                                        style={[styles.outlineButton, { flex: 0, borderColor: '#DC2626' }]}
                                        onPress={() => handleRespondInvite(inv, false)}
                                    >
                                        <Text style={[styles.outlineButtonText, { color: '#DC2626' }]}>Decline</Text>
                                    </Pressable>
                                    <Pressable
                                        style={[styles.primaryButton, { flex: 0, paddingHorizontal: 24 }]}
                                        onPress={() => handleRespondInvite(inv, true)}
                                    >
                                        <Text style={styles.primaryButtonText}>Accept</Text>
                                    </Pressable>
                                </RNView>
                            </RNView>
                        ))}

                        {recoveryRequests.map((req) => (
                            <RNView key={req.request_id} style={styles.card}>
                                <Text style={styles.dutyTitle}>Recovery Request</Text>
                                <Text style={styles.dutyDescription}>
                                    {req.display_name || req.user_id} is trying to recover their account. Do you approve?
                                </Text>
                                <RNView style={styles.formActions}>
                                    <Pressable
                                        style={[styles.outlineButton, { flex: 0, borderColor: '#DC2626' }]}
                                        onPress={() => handleApproveRecovery(req, false)}
                                    >
                                        <Text style={[styles.outlineButtonText, { color: '#DC2626' }]}>Deny</Text>
                                    </Pressable>
                                    <Pressable
                                        style={[styles.primaryButton, { flex: 0, paddingHorizontal: 24 }]}
                                        onPress={() => handleApproveRecovery(req, true)}
                                    >
                                        <Text style={styles.primaryButtonText}>Approve</Text>
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

const styles = StyleSheet.create({
    screen: { flex: 1, backgroundColor: '#F8FAFB' },
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
        color: '#94A3B8',
        letterSpacing: 0.8,
        marginTop: 24,
        marginBottom: 6,
    },
    sectionDescription: {
        fontSize: 13,
        color: '#94A3B8',
        marginBottom: 12,
        lineHeight: 18,
    },

    card: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 8,
    },
    infoCard: {
        flexDirection: 'row',
        alignItems: 'flex-start',
        gap: 10,
        backgroundColor: '#FFFBEB',
        borderRadius: 12,
        padding: 14,
        marginBottom: 8,
    },
    infoText: {
        flex: 1,
        fontSize: 13,
        color: '#92400E',
        lineHeight: 18,
    },

    fieldLabel: {
        fontSize: 12,
        fontWeight: '600',
        color: '#94A3B8',
        marginBottom: 6,
        textTransform: 'uppercase',
        letterSpacing: 0.3,
    },
    helperText: {
        fontSize: 13,
        color: '#94A3B8',
        lineHeight: 18,
        marginBottom: 12,
    },
    input: {
        backgroundColor: '#F1F5F9',
        borderRadius: 10,
        paddingHorizontal: 14,
        paddingVertical: 12,
        fontSize: 16,
        color: '#0F172A',
        marginBottom: 12,
    },

    primaryButton: {
        backgroundColor: '#00BCF2',
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
        color: '#00BCF2',
        fontSize: 14,
        fontWeight: '500',
    },
    outlineButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        borderWidth: 1,
        borderColor: '#00BCF2',
        borderRadius: 10,
        paddingVertical: 12,
        paddingHorizontal: 16,
    },
    outlineButtonText: {
        color: '#00BCF2',
        fontSize: 15,
        fontWeight: '600',
    },
    cancelText: {
        color: '#94A3B8',
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
        borderColor: '#E2E8F0',
        borderRadius: 8,
        paddingVertical: 10,
    },
    methodOptionActive: {
        borderColor: '#00BCF2',
        backgroundColor: '#F0FAFF',
    },
    methodText: {
        fontSize: 14,
        fontWeight: '500',
        color: '#94A3B8',
    },
    methodTextActive: {
        color: '#00BCF2',
    },

    // Status row (codes, etc.)
    statusRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        marginBottom: 12,
    },
    statusText: {
        fontSize: 14,
        color: '#0F172A',
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
        backgroundColor: '#F1F5F9',
        borderRadius: 6,
        paddingVertical: 6,
        paddingHorizontal: 10,
    },
    codeText: {
        fontSize: 13,
        fontFamily: 'Inter',
        color: '#0F172A',
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
        borderBottomColor: '#F1F5F9',
    },
    guardianName: {
        fontSize: 14,
        color: '#0F172A',
        fontWeight: '500',
    },
    guardianStatus: {
        fontSize: 12,
        color: '#94A3B8',
        textTransform: 'capitalize',
    },

    // Device row
    deviceRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        paddingVertical: 10,
        borderBottomWidth: 0.5,
        borderBottomColor: '#F1F5F9',
    },
    deviceLabel: {
        fontSize: 14,
        color: '#0F172A',
        fontWeight: '500',
    },
    deviceDetail: {
        fontSize: 12,
        color: '#94A3B8',
    },

    // Guardian duties
    dutyTitle: {
        fontSize: 15,
        fontWeight: '600',
        color: '#0F172A',
        marginBottom: 4,
    },
    dutyDescription: {
        fontSize: 13,
        color: '#64748B',
        lineHeight: 18,
        marginBottom: 8,
    },

    // Empty state
    emptyCard: {
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 24,
        gap: 8,
    },
    emptyText: {
        fontSize: 14,
        color: '#C7C7CC',
    },
});
