// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Recover Account flow — for users who lost access to their device.
 *
 * Steps:
 * 1. Enter your 24-word BIP39 recovery phrase
 * 2. Wait for guardian approvals (if guardians are configured)
 * 3. Account recovered → register new FIDO2 credential
 *
 * This page supports async recovery: the user can close the app and come back.
 * Recovery state is persisted via secure storage.
 */

import { Ionicons } from '@expo/vector-icons';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import * as Crypto from 'expo-crypto';
import { useRouter } from 'expo-router';
import { useState, useEffect, useCallback, useRef } from 'react';
import {
    StyleSheet,
    ScrollView,
    Pressable,
    View as RNView,
    TextInput,
    Alert,
    ActivityIndicator,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import { BIP39_WORDLIST, BIP39_WORDSET } from '@/services/bip39-wordlist';
import { register as fido2Register } from '@/services/fido2';
import {
    beginRecovery,
    getRecoveryStatus,
    completeRecovery,
    type RecoveryBeginResult,
    type RecoveryStatusResult,
} from '@/services/recovery-api';
import { useAuthStore } from '@/stores/auth';
import { useProfileStore } from '@/stores/profile';
import * as Storage from '@/utils/storage';
import * as NativeKeys from '../../modules/native-keys/src/index';

const RECOVERY_STATE_KEY = '@privasys/recovery-state';

/**
 * Validate the BIP39 checksum of a 24-word phrase: the final 8 bits of the
 * 264-bit word-index string must equal the first byte of SHA-256 over the
 * 256-bit entropy. A mistyped word that is still in the wordlist slips past
 * the dictionary check but fails this with 255/256 probability.
 */
function bip39ChecksumValid(words: string[]): boolean {
    if (words.length !== 24) return false;
    const indices = words.map((w) => BIP39_WORDLIST.indexOf(w));
    if (indices.some((i) => i < 0)) return false;
    let bits = '';
    for (const i of indices) bits += i.toString(2).padStart(11, '0');
    const entropy = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        entropy[i] = parseInt(bits.slice(i * 8, (i + 1) * 8), 2);
    }
    const expected = sha256(entropy)[0].toString(2).padStart(8, '0');
    return bits.slice(256) === expected;
}

interface RecoveryState {
    requestId: string;
    userId: string;
    status: string;
    guardiansRequired: number;
    guardiansApproved: number;
    expiresAt: string;
}

type FlowStep = 'enter-code' | 'waiting' | 'approved' | 'completed' | 'restored' | 'expired';

export default function RecoverAccountScreen() {
    const insets = useSafeAreaInsets();
    const router = useRouter();

    const [step, setStep] = useState<FlowStep>('enter-code');
    const [codeInput, setCodeInput] = useState('');
    const [submitting, setSubmitting] = useState(false);
    const [completing, setCompleting] = useState(false);
    const [registering, setRegistering] = useState(false);
    const [recoveryState, setRecoveryState] = useState<RecoveryState | null>(null);
    const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

    // Load persisted recovery state on mount.
    useEffect(() => {
        (async () => {
            try {
                const saved = await Storage.getItemAsync(RECOVERY_STATE_KEY);
                if (saved) {
                    const state: RecoveryState = JSON.parse(saved);
                    // Check if expired.
                    if (new Date(state.expiresAt) < new Date()) {
                        await Storage.deleteItemAsync(RECOVERY_STATE_KEY);
                        return;
                    }
                    setRecoveryState(state);
                    if (state.status === 'approved') {
                        setStep('approved');
                    } else if (state.status === 'completed') {
                        setStep('completed');
                    } else {
                        setStep('waiting');
                    }
                }
            } catch {
                // Ignore parse errors.
            }
        })();
    }, []);

    // Poll for status when waiting for guardians.
    useEffect(() => {
        if (step === 'waiting' && recoveryState) {
            const poll = async () => {
                try {
                    const status = await getRecoveryStatus(recoveryState.requestId);
                    const newState: RecoveryState = {
                        ...recoveryState,
                        status: status.status,
                        guardiansApproved: status.guardians_approved,
                    };
                    setRecoveryState(newState);
                    await Storage.setItemAsync(RECOVERY_STATE_KEY, JSON.stringify(newState));

                    if (status.status === 'approved') {
                        setStep('approved');
                    } else if (new Date(status.expires_at) < new Date()) {
                        setStep('expired');
                        await Storage.deleteItemAsync(RECOVERY_STATE_KEY);
                    }
                } catch (e) {
                    console.warn('[recover-account] poll error:', e);
                }
            };

            // Poll immediately then every 10 seconds.
            poll();
            pollRef.current = setInterval(poll, 10_000);
            return () => {
                if (pollRef.current) clearInterval(pollRef.current);
            };
        }
    }, [step, recoveryState?.requestId]);

    /**
     * Normalise the typed phrase to the canonical form the IdP hashes: 24
     * lowercase words separated by single spaces. Users paste/type phrases
     * with hyphens, commas, newlines or numbering — the server only splits on
     * whitespace, so anything else fails as "invalid phrase" even when every
     * word is right. BIP39 words are pure a-z, so any non-letter is a
     * separator. A single-token input is passed through untouched (legacy
     * recovery codes are not word phrases).
     */
    const normalizePhrase = (raw: string): { phrase: string; words: number } => {
        const tokens = raw.toLowerCase().match(/[a-z]+/g) ?? [];
        if (tokens.length <= 1) return { phrase: raw.trim(), words: tokens.length };
        return { phrase: tokens.join(' '), words: tokens.length };
    };

    const handleSubmitCode = async () => {
        if (!codeInput.trim()) return;
        const { phrase, words } = normalizePhrase(codeInput);
        // A word phrase must be exactly 24 words — catch miscounts locally
        // with a specific message instead of a generic server rejection.
        if (words > 1 && words !== 24) {
            Alert.alert(
                'Check Your Phrase',
                `A recovery phrase has 24 words, but ${words} ${words === 1 ? 'was' : 'were'} entered. ` +
                'Separate the words with spaces and check none are missing or duplicated.'
            );
            return;
        }
        if (words === 24) {
            const list = phrase.split(' ');
            // Dictionary check: every word must be a BIP39 word. Report the
            // exact positions so the user can fix their transcription.
            const unknown = list
                .map((w, i) => ({ w, i }))
                .filter(({ w }) => !BIP39_WORDSET.has(w));
            if (unknown.length > 0) {
                Alert.alert(
                    'Check Your Phrase',
                    'These are not recovery words — check your transcription: ' +
                    unknown.map(({ w, i }) => `#${i + 1} “${w}”`).join(', ')
                );
                return;
            }
            // Checksum check: catches a valid-but-wrong word (e.g. "brave" for
            // "bravo") that the dictionary check cannot. Server-generated
            // phrases always carry a valid checksum, so allow an explicit
            // override only for unusual manually-created phrases.
            if (!bip39ChecksumValid(list)) {
                Alert.alert(
                    'Possible Typo',
                    'The phrase does not pass its built-in consistency check — one or more words are likely mistyped. Double-check against your written copy.',
                    [
                        { text: 'Let me fix it', style: 'cancel' },
                        { text: 'Submit anyway', style: 'destructive', onPress: () => void submitPhrase(phrase) },
                    ]
                );
                return;
            }
        }
        await submitPhrase(phrase);
    };

    const submitPhrase = async (phrase: string) => {
        setSubmitting(true);
        try {
            // BIP39 24-word phrase has 256 bits of entropy — no device
            // attestation, no rate limiting required.
            const res: RecoveryBeginResult = await beginRecovery(phrase);
            const state: RecoveryState = {
                requestId: res.request_id,
                userId: res.user_id,
                status: res.status,
                guardiansRequired: res.guardians_required,
                guardiansApproved: res.guardians_approved,
                expiresAt: res.expires_at,
            };
            setRecoveryState(state);
            await Storage.setItemAsync(RECOVERY_STATE_KEY, JSON.stringify(state));

            if (res.status === 'approved') {
                setStep('approved');
            } else {
                setStep('waiting');
            }
            setCodeInput('');
        } catch (e: any) {
            Alert.alert('Invalid Code', e.message || 'The recovery code was not recognized. Please try again.');
        } finally {
            setSubmitting(false);
        }
    };

    const handleComplete = async () => {
        if (!recoveryState) return;
        setCompleting(true);
        try {
            await completeRecovery(recoveryState.requestId);
            const newState = { ...recoveryState, status: 'completed' };
            setRecoveryState(newState);
            await Storage.setItemAsync(RECOVERY_STATE_KEY, JSON.stringify(newState));
            setStep('completed');
        } catch (e: any) {
            Alert.alert('Error', e.message || 'Failed to complete recovery.');
        } finally {
            setCompleting(false);
        }
    };

    /**
     * The recovery last mile: bind THIS device to the recovered account.
     * `complete` revoked the account's old credentials server-side; register a
     * fresh FIDO2 credential with the recovered user id as the userHandle so
     * the IdP attaches it to the same `user_id` (roles, app ownerships and
     * recovery settings all follow it). Two-phase swap: the new credential is
     * created under its own unique hardware-key alias and persisted BEFORE any
     * previous privasys.id credential is removed — a failure at any point
     * leaves the existing credential untouched.
     */
    const handleRegisterRecovered = async () => {
        if (!recoveryState) return;
        setRegistering(true);
        try {
            const keyAlias = `fido2-privasys.id-${bytesToHex(Crypto.getRandomBytes(4))}`;
            const profile = useProfileStore.getState().profile;
            const result = await fido2Register(
                'privasys.id',
                keyAlias,
                '', // no browser ceremony to relay
                profile?.displayName,
                recoveryState.userId,
            );

            const auth = useAuthStore.getState();
            const old = auth.getCredentialForRp('privasys.id');
            auth.addCredential({
                credentialId: result.credentialId,
                rpId: 'privasys.id',
                origin: 'privasys.id',
                keyAlias,
                userHandle: result.userHandle,
                userName: result.userName,
                registeredAt: Math.floor(Date.now() / 1000),
                serverRpId: result.serverRpId,
            });
            // Only now retire the superseded credential (the rotated identity).
            if (old && old.credentialId !== result.credentialId) {
                auth.removeCredential(old.credentialId);
                const aliasStillUsed = useAuthStore
                    .getState()
                    .credentials.some((c) => c.keyAlias === old.keyAlias);
                if (!aliasStillUsed && old.keyAlias !== keyAlias) {
                    try {
                        await NativeKeys.deleteKey(old.keyAlias);
                    } catch (e: any) {
                        console.warn('[recover-account] old key cleanup failed:', e?.message);
                    }
                }
            }

            await Storage.deleteItemAsync(RECOVERY_STATE_KEY);
            setStep('restored');
        } catch (e: any) {
            console.error('[recover-account] recovered registration failed:', e?.message, e);
            Alert.alert(
                'Registration Failed',
                `Could not register this device to the recovered account: ${e?.message ?? e}. ` +
                'Your existing sign-ins are unchanged — you can retry.'
            );
        } finally {
            setRegistering(false);
        }
    };

    const handleDismiss = async () => {
        await Storage.deleteItemAsync(RECOVERY_STATE_KEY);
        router.back();
    };

    const handleCancel = () => {
        Alert.alert(
            'Cancel Recovery',
            'Are you sure? You will need a new recovery code to try again.',
            [
                { text: 'Keep Waiting', style: 'cancel' },
                {
                    text: 'Cancel Recovery',
                    style: 'destructive',
                    onPress: async () => {
                        await Storage.deleteItemAsync(RECOVERY_STATE_KEY);
                        setRecoveryState(null);
                        setStep('enter-code');
                    },
                },
            ],
        );
    };

    return (
        <RNView style={styles.screen}>
            {/* Header */}
            <RNView style={[styles.header, { paddingTop: insets.top + 8 }]}>
                <Pressable onPress={() => router.back()} hitSlop={12} style={styles.backButton}>
                    <Ionicons name="chevron-back" size={24} color="#FFFFFF" />
                </Pressable>
                <Text style={styles.headerTitle}>Recover Account</Text>
                <RNView style={{ width: 32 }} />
            </RNView>

            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={styles.scrollContent}
                showsVerticalScrollIndicator={false}
                keyboardShouldPersistTaps="handled"
            >
                {/* Step 1: Enter recovery code */}
                {step === 'enter-code' && (
                    <>
                        <RNView style={styles.iconContainer}>
                            <Ionicons name="key-outline" size={48} color="#00BCF2" />
                        </RNView>
                        <Text style={styles.title}>Enter Recovery Code</Text>
                        <Text style={styles.subtitle}>
                            Enter your 24-word recovery phrase to begin the account recovery process.
                        </Text>

                        <RNView style={styles.card}>
                            <Text style={styles.fieldLabel}>Recovery Phrase</Text>
                            <TextInput
                                style={[styles.input, { minHeight: 100, textAlignVertical: 'top' }]}
                                value={codeInput}
                                onChangeText={setCodeInput}
                                placeholder="word1 word2 word3 ... word24"
                                placeholderTextColor="#94A3B8"
                                autoCapitalize="none"
                                autoCorrect={false}
                                autoFocus
                                multiline
                            />
                            <Pressable
                                style={[styles.primaryButton, (submitting || !codeInput.trim()) && { opacity: 0.6 }]}
                                onPress={handleSubmitCode}
                                disabled={submitting || !codeInput.trim()}
                            >
                                {submitting ? (
                                    <ActivityIndicator color="#FFFFFF" size="small" />
                                ) : (
                                    <Text style={styles.primaryButtonText}>Begin Recovery</Text>
                                )}
                            </Pressable>
                        </RNView>
                    </>
                )}

                {/* Step 2: Waiting for guardians */}
                {step === 'waiting' && recoveryState && (
                    <>
                        <RNView style={styles.iconContainer}>
                            <ActivityIndicator color="#00BCF2" size="large" />
                        </RNView>
                        <Text style={styles.title}>Waiting for Guardians</Text>
                        <Text style={styles.subtitle}>
                            Your recovery request has been sent to your trusted guardians.
                            You can close this screen and come back — we'll keep checking.
                        </Text>

                        <RNView style={styles.card}>
                            <RNView style={styles.progressRow}>
                                <Text style={styles.progressLabel}>Guardian Approvals</Text>
                                <Text style={styles.progressValue}>
                                    {recoveryState.guardiansApproved} / {recoveryState.guardiansRequired}
                                </Text>
                            </RNView>
                            <RNView style={styles.progressBar}>
                                <RNView
                                    style={[
                                        styles.progressFill,
                                        {
                                            width: recoveryState.guardiansRequired > 0
                                                ? `${Math.min(100, (recoveryState.guardiansApproved / recoveryState.guardiansRequired) * 100)}%`
                                                : '0%',
                                        },
                                    ]}
                                />
                            </RNView>
                            <Text style={styles.expiresText}>
                                Expires: {new Date(recoveryState.expiresAt).toLocaleString()}
                            </Text>
                        </RNView>

                        <Pressable style={styles.secondaryButton} onPress={handleCancel}>
                            <Text style={[styles.secondaryButtonText, { color: '#DC2626' }]}>Cancel Recovery</Text>
                        </Pressable>
                    </>
                )}

                {/* Step 3: Approved — complete recovery */}
                {step === 'approved' && recoveryState && (
                    <>
                        <RNView style={styles.iconContainer}>
                            <Ionicons name="checkmark-circle" size={48} color="#34E89E" />
                        </RNView>
                        <Text style={styles.title}>Recovery Approved</Text>
                        <Text style={styles.subtitle}>
                            All required approvals have been received. Tap below to complete recovery
                            and re-register your device.
                        </Text>

                        <Pressable
                            style={[styles.primaryButton, completing && { opacity: 0.6 }]}
                            onPress={handleComplete}
                            disabled={completing}
                        >
                            {completing ? (
                                <ActivityIndicator color="#FFFFFF" size="small" />
                            ) : (
                                <Text style={styles.primaryButtonText}>Complete Recovery</Text>
                            )}
                        </Pressable>
                    </>
                )}

                {/* Step 4: Completed — the account is unlocked server-side; now
                    bind THIS device to it. Without this step the recovery is
                    incomplete: the old credentials were just revoked and
                    nothing signs for the account yet. */}
                {step === 'completed' && (
                    <>
                        <RNView style={styles.iconContainer}>
                            <Ionicons name="shield-checkmark" size={48} color="#34E89E" />
                        </RNView>
                        <Text style={styles.title}>Account Recovered</Text>
                        <Text style={styles.subtitle}>
                            One step left: register this device to the recovered account. This
                            creates a new passkey bound to your recovered identity — your roles
                            and app ownerships come back with it.
                        </Text>

                        <Pressable
                            style={[styles.primaryButton, registering && { opacity: 0.6 }]}
                            onPress={handleRegisterRecovered}
                            disabled={registering}
                        >
                            {registering ? (
                                <ActivityIndicator color="#FFFFFF" />
                            ) : (
                                <Text style={styles.primaryButtonText}>Register This Device</Text>
                            )}
                        </Pressable>
                    </>
                )}

                {/* Step 5: Restored — device bound to the recovered account. */}
                {step === 'restored' && (
                    <>
                        <RNView style={styles.iconContainer}>
                            <Ionicons name="checkmark-circle" size={48} color="#34E89E" />
                        </RNView>
                        <Text style={styles.title}>Device Restored</Text>
                        <Text style={styles.subtitle}>
                            This device now signs in as your recovered account. Consider
                            generating a fresh recovery phrase in Settings → Account Recovery —
                            recovery phrases are single-use.
                        </Text>

                        <Pressable style={styles.primaryButton} onPress={handleDismiss}>
                            <Text style={styles.primaryButtonText}>Done</Text>
                        </Pressable>
                    </>
                )}

                {/* Expired */}
                {step === 'expired' && (
                    <>
                        <RNView style={styles.iconContainer}>
                            <Ionicons name="time-outline" size={48} color="#F59E0B" />
                        </RNView>
                        <Text style={styles.title}>Recovery Expired</Text>
                        <Text style={styles.subtitle}>
                            Your recovery request has expired. Please start a new recovery with a different recovery code.
                        </Text>

                        <Pressable
                            style={styles.primaryButton}
                            onPress={() => {
                                setRecoveryState(null);
                                setStep('enter-code');
                            }}
                        >
                            <Text style={styles.primaryButtonText}>Try Again</Text>
                        </Pressable>
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

    iconContainer: {
        alignItems: 'center',
        marginTop: 40,
        marginBottom: 20,
    },
    title: {
        fontSize: 22,
        fontWeight: '700',
        color: '#0F172A',
        textAlign: 'center',
        marginBottom: 8,
    },
    subtitle: {
        fontSize: 15,
        color: '#64748B',
        textAlign: 'center',
        lineHeight: 22,
        marginBottom: 24,
        paddingHorizontal: 8,
    },

    card: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 16,
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
        fontFamily: 'Inter',
        letterSpacing: 1,
    },

    primaryButton: {
        backgroundColor: '#00BCF2',
        borderRadius: 10,
        paddingVertical: 14,
        alignItems: 'center' as const,
    },
    primaryButtonText: {
        color: '#FFFFFF',
        fontSize: 16,
        fontWeight: '600',
    },
    secondaryButton: {
        alignItems: 'center' as const,
        paddingVertical: 12,
        marginTop: 8,
    },
    secondaryButtonText: {
        fontSize: 15,
        fontWeight: '500',
    },

    // Progress
    progressRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 8,
    },
    progressLabel: {
        fontSize: 14,
        color: '#64748B',
        fontWeight: '500',
    },
    progressValue: {
        fontSize: 16,
        color: '#0F172A',
        fontWeight: '700',
    },
    progressBar: {
        height: 8,
        backgroundColor: '#E2E8F0',
        borderRadius: 4,
        overflow: 'hidden',
        marginBottom: 12,
    },
    progressFill: {
        height: '100%',
        backgroundColor: '#34E89E',
        borderRadius: 4,
    },
    expiresText: {
        fontSize: 12,
        color: '#94A3B8',
        textAlign: 'center',
    },
});
