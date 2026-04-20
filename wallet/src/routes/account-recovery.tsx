// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Account Recovery management screen — configure recovery options.
 *
 * Sections:
 * - Email Verification: verify your email for recovery
 * - Recovery Codes: generate and manage backup codes
 * - Trusted Guardians: invite/manage k-of-n guardian contacts
 * - Devices: view registered devices (FIDO2 credentials on IdP)
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
    sendVerificationEmail,
    verifyEmailCode,
    generateRecoveryCodes,
    checkRecoveryCodes,
    listGuardians,
    inviteGuardian,
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
import { useProfileStore } from '@/stores/profile';

export default function AccountRecoveryScreen() {
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const profile = useProfileStore((s) => s.profile);

    // Access token — for now we pass empty string (will be wired when SDK auth is ready).
    // TODO: get a real access token from the IdP for the wallet user.
    const accessToken = '';

    const [refreshing, setRefreshing] = useState(false);
    const [loading, setLoading] = useState(true);

    // Email verification
    const [emailInput, setEmailInput] = useState(profile?.email || '');
    const [verificationId, setVerificationId] = useState('');
    const [otpInput, setOtpInput] = useState('');
    const [emailVerified, setEmailVerified] = useState(false);
    const [sendingOtp, setSendingOtp] = useState(false);
    const [verifyingOtp, setVerifyingOtp] = useState(false);

    // Recovery codes
    const [codesStatus, setCodesStatus] = useState<{ has_codes: boolean; remaining_codes: number } | null>(null);
    const [newCodes, setNewCodes] = useState<string[] | null>(null);
    const [generatingCodes, setGeneratingCodes] = useState(false);

    // Guardians
    const [guardians, setGuardians] = useState<GuardianInfo[]>([]);
    const [guardianThreshold, setGuardianThreshold] = useState(0);
    const [guardianEmail, setGuardianEmail] = useState('');
    const [thresholdInput, setThresholdInput] = useState('1');
    const [showInviteForm, setShowInviteForm] = useState(false);
    const [inviting, setInviting] = useState(false);

    // Devices
    const [devices, setDevices] = useState<DeviceInfo[]>([]);

    // Guardian duties (invites from others + recovery requests)
    const [pendingInvites, setPendingInvites] = useState<GuardianInvite[]>([]);
    const [recoveryRequests, setRecoveryRequests] = useState<RecoveryRequestInfo[]>([]);

    const loadData = useCallback(async () => {
        if (!accessToken) {
            setLoading(false);
            return;
        }
        try {
            const [codesRes, guardiansRes, devicesRes, invitesRes, requestsRes] = await Promise.all([
                checkRecoveryCodes(accessToken).catch(() => null),
                listGuardians(accessToken).catch(() => null),
                listDevices(accessToken).catch(() => null),
                listGuardianInvites(accessToken).catch(() => null),
                listRecoveryRequests(accessToken).catch(() => null),
            ]);
            if (codesRes) setCodesStatus(codesRes);
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
    }, [accessToken]);

    useEffect(() => { loadData(); }, [loadData]);

    const onRefresh = useCallback(async () => {
        setRefreshing(true);
        await loadData();
        setRefreshing(false);
    }, [loadData]);

    // ── Email verification handlers ──

    const handleSendOtp = async () => {
        if (!emailInput.trim()) return;
        setSendingOtp(true);
        try {
            const res = await sendVerificationEmail(emailInput.trim());
            setVerificationId(res.verification_id);
            Alert.alert('Code Sent', `A verification code has been sent to ${emailInput.trim()}.`);
        } catch (e: any) {
            Alert.alert('Error', e.message);
        } finally {
            setSendingOtp(false);
        }
    };

    const handleVerifyOtp = async () => {
        if (!otpInput.trim() || !emailInput.trim()) return;
        setVerifyingOtp(true);
        try {
            await verifyEmailCode(emailInput.trim(), otpInput.trim());
            setEmailVerified(true);
            setOtpInput('');
            Alert.alert('Verified', 'Your email has been verified successfully.');
        } catch (e: any) {
            Alert.alert('Error', e.message);
        } finally {
            setVerifyingOtp(false);
        }
    };

    // ── Recovery codes handlers ──

    const handleGenerateCodes = async () => {
        Alert.alert(
            'Generate Recovery Codes',
            codesStatus?.has_codes
                ? 'This will replace your existing recovery codes. The old codes will no longer work.'
                : 'Generate 12 one-time recovery codes. Save them securely.',
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Generate',
                    onPress: async () => {
                        setGeneratingCodes(true);
                        try {
                            const res = await generateRecoveryCodes(accessToken);
                            setNewCodes(res.codes);
                            setCodesStatus({ has_codes: true, remaining_codes: res.codes.length });
                        } catch (e: any) {
                            Alert.alert('Error', e.message);
                        } finally {
                            setGeneratingCodes(false);
                        }
                    },
                },
            ],
        );
    };

    // ── Guardian handlers ──

    const handleInviteGuardian = async () => {
        if (!guardianEmail.trim()) return;
        const threshold = Math.max(1, parseInt(thresholdInput, 10) || 1);
        setInviting(true);
        try {
            await inviteGuardian(accessToken, guardianEmail.trim(), threshold);
            setGuardianEmail('');
            setShowInviteForm(false);
            Alert.alert('Invited', 'Guardian invitation sent.');
            await loadData();
        } catch (e: any) {
            Alert.alert('Error', e.message);
        } finally {
            setInviting(false);
        }
    };

    const handleRemoveGuardian = (g: GuardianInfo) => {
        Alert.alert('Remove Guardian', `Remove ${g.guardian_email} as a guardian?`, [
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
            `${approved ? 'Approve' : 'Deny'} the recovery request from ${req.user_email || req.user_id}?`,
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
                <Text style={styles.headerTitle}>Account Recovery</Text>
                <RNView style={{ width: 32 }} />
            </RNView>

            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={styles.scrollContent}
                showsVerticalScrollIndicator={false}
                refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#00BCF2" />}
            >
                {notConfigured && (
                    <RNView style={styles.infoCard}>
                        <Ionicons name="information-circle-outline" size={20} color="#F59E0B" />
                        <Text style={styles.infoText}>
                            Recovery management requires an authenticated session with Privasys ID. This will be enabled in a future update.
                        </Text>
                    </RNView>
                )}

                {/* ── Email Verification ── */}
                <Text style={styles.sectionTitle}>EMAIL VERIFICATION</Text>
                <Text style={styles.sectionDescription}>
                    Verify your email address to enable account recovery. A 6-digit code will be sent to your email.
                </Text>

                <RNView style={styles.card}>
                    {emailVerified ? (
                        <RNView style={styles.verifiedRow}>
                            <Ionicons name="checkmark-circle" size={24} color="#34E89E" />
                            <RNView style={{ flex: 1 }}>
                                <Text style={styles.verifiedLabel}>Email Verified</Text>
                                <Text style={styles.verifiedEmail}>{emailInput}</Text>
                            </RNView>
                        </RNView>
                    ) : verificationId ? (
                        <>
                            <Text style={styles.fieldLabel}>Enter the 6-digit code sent to {emailInput}</Text>
                            <TextInput
                                style={styles.input}
                                value={otpInput}
                                onChangeText={setOtpInput}
                                placeholder="123456"
                                placeholderTextColor="#94A3B8"
                                keyboardType="number-pad"
                                maxLength={6}
                                autoFocus
                            />
                            <Pressable
                                style={[styles.primaryButton, verifyingOtp && { opacity: 0.6 }]}
                                onPress={handleVerifyOtp}
                                disabled={verifyingOtp || otpInput.length < 6}
                            >
                                {verifyingOtp ? (
                                    <ActivityIndicator color="#FFFFFF" size="small" />
                                ) : (
                                    <Text style={styles.primaryButtonText}>Verify Code</Text>
                                )}
                            </Pressable>
                            <Pressable style={styles.secondaryButton} onPress={() => setVerificationId('')}>
                                <Text style={styles.secondaryButtonText}>Resend Code</Text>
                            </Pressable>
                        </>
                    ) : (
                        <>
                            <Text style={styles.fieldLabel}>Email address</Text>
                            <TextInput
                                style={styles.input}
                                value={emailInput}
                                onChangeText={setEmailInput}
                                placeholder="you@example.com"
                                placeholderTextColor="#94A3B8"
                                keyboardType="email-address"
                                autoCapitalize="none"
                                autoCorrect={false}
                            />
                            <Pressable
                                style={[styles.primaryButton, (sendingOtp || !emailInput.trim()) && { opacity: 0.6 }]}
                                onPress={handleSendOtp}
                                disabled={sendingOtp || !emailInput.trim() || notConfigured}
                            >
                                {sendingOtp ? (
                                    <ActivityIndicator color="#FFFFFF" size="small" />
                                ) : (
                                    <Text style={styles.primaryButtonText}>Send Verification Code</Text>
                                )}
                            </Pressable>
                        </>
                    )}
                </RNView>

                {/* ── Recovery Codes ── */}
                <Text style={styles.sectionTitle}>RECOVERY CODES</Text>
                <Text style={styles.sectionDescription}>
                    One-time backup codes to regain access if you lose your device. Store them in a safe place.
                </Text>

                {newCodes ? (
                    <RNView style={styles.card}>
                        <Text style={[styles.fieldLabel, { marginBottom: 8 }]}>
                            Save these codes — they won't be shown again
                        </Text>
                        <RNView style={styles.codesGrid}>
                            {newCodes.map((code, i) => (
                                <RNView key={i} style={styles.codeItem}>
                                    <Text style={styles.codeText}>{code}</Text>
                                </RNView>
                            ))}
                        </RNView>
                        <Pressable
                            style={styles.secondaryButton}
                            onPress={() => setNewCodes(null)}
                        >
                            <Text style={styles.secondaryButtonText}>I've saved these codes</Text>
                        </Pressable>
                    </RNView>
                ) : (
                    <RNView style={styles.card}>
                        {codesStatus ? (
                            <RNView style={styles.statusRow}>
                                <Ionicons
                                    name={codesStatus.has_codes ? 'checkmark-circle' : 'alert-circle-outline'}
                                    size={20}
                                    color={codesStatus.has_codes ? '#34E89E' : '#F59E0B'}
                                />
                                <Text style={styles.statusText}>
                                    {codesStatus.has_codes
                                        ? `${codesStatus.remaining_codes} recovery code${codesStatus.remaining_codes !== 1 ? 's' : ''} remaining`
                                        : 'No recovery codes configured'}
                                </Text>
                            </RNView>
                        ) : (
                            <RNView style={styles.statusRow}>
                                <Ionicons name="alert-circle-outline" size={20} color="#94A3B8" />
                                <Text style={styles.statusText}>Recovery codes not set up</Text>
                            </RNView>
                        )}
                        <Pressable
                            style={[styles.primaryButton, (generatingCodes || notConfigured) && { opacity: 0.6 }]}
                            onPress={handleGenerateCodes}
                            disabled={generatingCodes || notConfigured}
                        >
                            {generatingCodes ? (
                                <ActivityIndicator color="#FFFFFF" size="small" />
                            ) : (
                                <Text style={styles.primaryButtonText}>
                                    {codesStatus?.has_codes ? 'Regenerate Codes' : 'Generate Recovery Codes'}
                                </Text>
                            )}
                        </Pressable>
                    </RNView>
                )}

                {/* ── Trusted Guardians ── */}
                <Text style={styles.sectionTitle}>TRUSTED GUARDIANS</Text>
                <Text style={styles.sectionDescription}>
                    Nominate trusted contacts who can approve your account recovery. They must be Privasys ID users.
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
                                    <Text style={styles.guardianEmail}>{g.guardian_email}</Text>
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
                        <RNView style={styles.formActions}>
                            <Pressable onPress={() => setShowInviteForm(false)}>
                                <Text style={styles.cancelText}>Cancel</Text>
                            </Pressable>
                            <Pressable
                                style={[styles.primaryButton, { flex: 0, paddingHorizontal: 24 }, (inviting || !guardianEmail.trim()) && { opacity: 0.6 }]}
                                onPress={handleInviteGuardian}
                                disabled={inviting || !guardianEmail.trim()}
                            >
                                {inviting ? (
                                    <ActivityIndicator color="#FFFFFF" size="small" />
                                ) : (
                                    <Text style={styles.primaryButtonText}>Send Invite</Text>
                                )}
                            </Pressable>
                        </RNView>
                    </RNView>
                ) : (
                    <Pressable
                        style={[styles.outlineButton, notConfigured && { opacity: 0.4 }]}
                        onPress={() => setShowInviteForm(true)}
                        disabled={notConfigured}
                    >
                        <Ionicons name="person-add-outline" size={18} color="#00BCF2" />
                        <Text style={styles.outlineButtonText}>Invite Guardian</Text>
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
                                    {inv.user_email || inv.user_id} wants you as a recovery guardian.
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
                                    {req.user_email || req.user_id} is trying to recover their account. Do you approve?
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

    // Email verified
    verifiedRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12,
    },
    verifiedLabel: {
        fontSize: 15,
        fontWeight: '600',
        color: '#0F172A',
    },
    verifiedEmail: {
        fontSize: 13,
        color: '#64748B',
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
    guardianEmail: {
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
