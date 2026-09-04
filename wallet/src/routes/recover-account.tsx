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
import { bytesToHex } from '@noble/hashes/utils.js';
import * as Crypto from 'expo-crypto';
import { useRouter } from 'expo-router';
import { useState, useEffect, useMemo, useRef } from 'react';
import {
    StyleSheet,
    ScrollView,
    Pressable,
    View as RNView,
    TextInput,
    Alert,
    ActivityIndicator,
    KeyboardAvoidingView,
    Platform,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { bip39ChecksumValid } from '@/services/bip39';
import { useTranslation } from 'react-i18next';
import { BIP39_WORDLIST, BIP39_WORDSET } from '@/services/bip39-wordlist';
import { restoreSovereignSecrets, stashRecoveredPairwiseSeed } from '@/services/sovereign';
import { register as fido2Register } from '@/services/fido2';
import { canonicalUserHandle } from '@/services/privasys-id';
import {
    beginRecovery,
    getRecoveryStatus,
    completeRecovery,
    // Declared in the service, not here, so the wallet wipe can clear it too.
    RECOVERY_STATE_KEY,
    type RecoveryBeginResult,
} from '@/services/recovery-api';
import { useAuthStore } from '@/stores/auth';
import { useProfileStore } from '@/stores/profile';
import * as Storage from '@/utils/storage';
import * as NativeKeys from '../../modules/native-keys/src/index';

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
    const { t } = useTranslation();
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);

    const [step, setStep] = useState<FlowStep>('enter-code');
    const [codeInput, setCodeInput] = useState('');
    const [submitting, setSubmitting] = useState(false);
    const [completing, setCompleting] = useState(false);
    const [completeError, setCompleteError] = useState(false);
    const [registering, setRegistering] = useState(false);
    const [recoveryState, setRecoveryState] = useState<RecoveryState | null>(null);
    const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
    const autoCompletedRef = useRef(false);
    // The entered phrase, held in memory across the ceremony so the
    // sovereign backup can be unwrapped after this device re-registers.
    // Deliberately NOT persisted: if the app restarts mid-recovery the
    // restore is skipped (the user still holds the phrase on paper; the
    // blob remains server-side).
    const enteredPhraseRef = useRef<string | null>(null);

    // Load persisted recovery state on mount.
    useEffect(() => {
        (async () => {
            try {
                const saved = await Storage.getItemAsync(RECOVERY_STATE_KEY);
                if (saved) {
                    const state: RecoveryState = JSON.parse(saved);
                    // Say so rather than silently reopening on the phrase
                    // screen: a holder who left mid-flow and came back an hour
                    // later otherwise sees no explanation for why they are
                    // starting again, and reads the fresh prompt as the app
                    // having lost their progress.
                    if (new Date(state.expiresAt) < new Date()) {
                        await Storage.deleteItemAsync(RECOVERY_STATE_KEY);
                        Alert.alert(t('recover.expiredTitle'), t('recover.expiredBody'));
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

    /**
     * Live per-word feedback while the phrase is typed. Each completed word is
     * checked against the BIP39 wordlist immediately; the word still being
     * typed (no separator after it yet) stays neutral while it is a valid
     * prefix of some wordlist word, and only turns red once no completion
     * exists. Catches transcription errors at the word they happen instead of
     * at submit time.
     */
    const typedWords = codeInput.toLowerCase().match(/[a-z]+/g) ?? [];
    const inputEndsMidWord = /[a-z]$/i.test(codeInput);
    const wordStates = typedWords.map((w, i) => {
        if (BIP39_WORDSET.has(w)) return { w, state: 'valid' as const };
        const isLastAndTyping = i === typedWords.length - 1 && inputEndsMidWord;
        if (isLastAndTyping && BIP39_WORDLIST.some((x) => x.startsWith(w))) {
            return { w, state: 'typing' as const };
        }
        return { w, state: 'invalid' as const };
    });

    const handleSubmitCode = async () => {
        if (!codeInput.trim()) return;
        const { phrase, words } = normalizePhrase(codeInput);
        // A word phrase must be exactly 24 words — catch miscounts locally
        // with a specific message instead of a generic server rejection.
        if (words > 1 && words !== 24) {
            // One whole sentence per plural form rather than a "was"/"were"
            // switch inside a template: agreement is not a two-way choice in
            // most of the languages we ship.
            Alert.alert(
                t('recover.checkPhraseTitle'),
                t('recover.wrongWordCount', { count: words })
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
                    t('recover.checkPhraseTitle'),
                    t('recover.unknownWords', {
                        words: unknown.map(({ w, i }) => t('recover.wordAt', { position: i + 1, word: w })).join(', ')
                    })
                );
                return;
            }
            // Checksum check: catches a valid-but-wrong word (e.g. "brave" for
            // "bravo") that the dictionary check cannot. Server-generated
            // phrases always carry a valid checksum, so allow an explicit
            // override only for unusual manually-created phrases.
            if (!bip39ChecksumValid(list)) {
                Alert.alert(
                    t('recover.possibleTypoTitle'),
                    t('recover.possibleTypoBody'),
                    [
                        { text: t('recover.letMeFixIt'), style: 'cancel' },
                        { text: t('recover.submitAnyway'), style: 'destructive', onPress: () => void submitPhrase(phrase) },
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
            enteredPhraseRef.current = phrase;
            setCodeInput('');
        } catch (e: any) {
            Alert.alert(t('recover.invalidCodeTitle'), e.message || t('recover.invalidCodeBody'));
        } finally {
            setSubmitting(false);
        }
    };

    const handleComplete = async () => {
        if (!recoveryState) return;
        setCompleting(true);
        setCompleteError(false);
        try {
            await completeRecovery(recoveryState.requestId);
            // Recovery deletes the account's recovery codes server-side, so the
            // old phrase is dead. Clear the "saved" flag → the nudge re-appears
            // until the user generates and writes down a fresh phrase.
            useAuthStore.getState().setRecoveryPhraseSaved(false);
            const newState = { ...recoveryState, status: 'completed' };
            setRecoveryState(newState);
            await Storage.setItemAsync(RECOVERY_STATE_KEY, JSON.stringify(newState));
            setStep('completed');
        } catch (e: any) {
            Alert.alert(t('common.error'), e.message || t('recover.completeFailed'));
            setCompleteError(true);
        } finally {
            setCompleting(false);
        }
    };

    // Auto-finalise once the approvals are in: completeRecovery is a server call
    // with no biometric, so there is no reason to make the user tap through it.
    // The next step (register) stays an explicit tap because it prompts
    // biometrics. Runs once per entry into 'approved'; on failure the screen
    // shows a Retry (completeError) rather than re-firing on every render.
    useEffect(() => {
        if (step === 'approved' && recoveryState && !autoCompletedRef.current) {
            autoCompletedRef.current = true;
            void handleComplete();
        }
        if (step !== 'approved') autoCompletedRef.current = false;
        // handleComplete closes over stable setters + recoveryState; the ref
        // guards against re-entry, so step is the only meaningful trigger.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [step, recoveryState?.requestId]);

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

            // Two accounts share the privasys.id rpId on this device: the
            // CANONICAL meta-account (lives in the dedicated `privasysId`
            // slot) and the pairwise platform identity (lives in
            // `credentials[]`). Which store the fresh credential belongs in —
            // and which previous credential it supersedes — follows from WHICH
            // account was recovered, never from the rpId alone: keying the
            // swap on rpId let recovering one account delete the other's
            // credential, and the unconditional slot write pointed the
            // meta-account at whatever identity was recovered last
            // (2026-07-30, the admin account incident).
            const auth = useAuthStore.getState();
            const canonicalHandle = await canonicalUserHandle();
            const isCanonical =
                canonicalHandle !== null && recoveryState.userId === canonicalHandle;
            // The superseded credential is the one registered to the SAME
            // account (matched by userHandle) — plus, for the canonical
            // account, any stray copy that ended up in credentials[] while
            // this flow was slot-unaware.
            const superseded = auth.credentials.filter(
                (c) =>
                    c.rpId === 'privasys.id' &&
                    c.credentialId !== result.credentialId &&
                    c.userHandle === recoveryState.userId,
            );

            if (isCanonical) {
                // Canonical account → the slot is its home; never credentials[].
                auth.setPrivasysId({
                    userId: recoveryState.userId,
                    credentialId: result.credentialId,
                    keyAlias,
                    sessionToken: result.sessionToken ?? '',
                    // Cache the fresh session when we got one; otherwise force a
                    // re-auth (which now uses the correct credentialId).
                    sessionExpiresAt: result.sessionToken ? Date.now() + 25 * 60 * 1000 : 0,
                });
            } else {
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
                // Adopt any canonical-account credential that ended up in
                // credentials[] (from the slot-unaware era) back into its
                // slot. In credentials[] it SHADOWS the pairwise platform
                // credential — getCredentialForRp('privasys.id') is
                // first-match, so sign-ins would ride the canonical account
                // and the portal would show an empty account. The hardware
                // key moves with the entry; nothing is deleted.
                if (canonicalHandle) {
                    const strayCanonical = auth.credentials.find(
                        (c) =>
                            c.rpId === 'privasys.id' &&
                            c.userHandle === canonicalHandle &&
                            c.credentialId !== result.credentialId,
                    );
                    if (strayCanonical) {
                        auth.setPrivasysId({
                            userId: canonicalHandle,
                            credentialId: strayCanonical.credentialId,
                            keyAlias: strayCanonical.keyAlias,
                            sessionToken: '',
                            sessionExpiresAt: 0,
                        });
                        auth.removeCredential(strayCanonical.credentialId);
                    }
                }
            }

            // Only now retire the superseded credential(s) of THIS account
            // (two-phase swap: the new one is persisted first).
            for (const old of superseded) {
                auth.removeCredential(old.credentialId);
                // The alias-still-used check must also cover the canonical
                // slot (outside credentials[]): deleting a key the slot still
                // references bricks the canonical credential.
                const postSwap = useAuthStore.getState();
                const aliasStillUsed =
                    postSwap.credentials.some((c) => c.keyAlias === old.keyAlias) ||
                    postSwap.privasysId?.keyAlias === old.keyAlias;
                if (!aliasStillUsed && old.keyAlias !== keyAlias) {
                    try {
                        await NativeKeys.deleteKey(old.keyAlias);
                    } catch (e: any) {
                        console.warn('[recover-account] old key cleanup failed:', e?.message);
                    }
                }
            }

            // Restore the sovereign backup (data root + pairwise seed): the
            // entered phrase — still in memory for the single-session flow —
            // unwraps the blob the old device stored. Best-effort: a
            // pre-framework account has no blob, and a restart mid-recovery
            // dropped the phrase; neither should fail the registration.
            const phrase = enteredPhraseRef.current;
            const sessionToken = result.sessionToken ?? '';
            if (phrase && sessionToken) {
                try {
                    const restored = await restoreSovereignSecrets(phrase, sessionToken);
                    if (restored?.pairwiseSeedHex) {
                        const prof = useProfileStore.getState().profile;
                        if (!prof) {
                            // Profile not created yet on this device: the
                            // creation paths prefer the stashed seed, which is
                            // what carries pairwise identities across devices.
                            await stashRecoveredPairwiseSeed(restored.pairwiseSeedHex);
                        } else if (prof.pairwiseSeed !== restored.pairwiseSeedHex) {
                            // A different seed is already in use on this
                            // device (possibly by another account) — replacing
                            // it would rotate every derived sub. Keep the
                            // device seed; the data root is still restored.
                            console.warn('[recover-account] recovered pairwise seed differs from the device seed; keeping the device seed');
                        }
                    }
                } catch (e: any) {
                    console.warn('[recover-account] sovereign restore failed:', e?.message);
                }
            }
            enteredPhraseRef.current = null;

            await Storage.deleteItemAsync(RECOVERY_STATE_KEY);
            setStep('restored');
        } catch (e: any) {
            console.error('[recover-account] recovered registration failed:', e?.message, e);
            // A retry button, because the alert says the sign-ins are unchanged
            // and the holder can try again, and then offered no way to. Backing
            // out of this screen is how a recovery gets abandoned half-done.
            Alert.alert(
                t('recover.registrationFailedTitle'),
                t('recover.registrationFailedBody', { reason: e?.message ?? e }),
                [
                    { text: t('common.cancel'), style: 'cancel' },
                    { text: t('common.retry'), onPress: () => { void handleRegisterRecovered(); } },
                ],
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
            t('recover.cancelTitle'),
            t('recover.cancelBody'),
            [
                { text: t('recover.keepWaiting'), style: 'cancel' },
                {
                    text: t('recover.cancelTitle'),
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
                <Text style={styles.headerTitle}>{t('profile.recoverAccount')}</Text>
                <RNView style={{ width: 32 }} />
            </RNView>

            <KeyboardAvoidingView
                style={{ flex: 1 }}
                behavior={Platform.OS === 'ios' ? 'padding' : undefined}
                // Offset the custom header so the keyboard shrinks the scroll
                // area correctly and the primary button scrolls into view.
                keyboardVerticalOffset={Platform.OS === 'ios' ? insets.top + 50 : 0}
            >
            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={[styles.scrollContent, { paddingBottom: insets.bottom + 32 }]}
                showsVerticalScrollIndicator={false}
                keyboardShouldPersistTaps="handled"
            >
                {/* Step 1: Enter recovery code */}
                {step === 'enter-code' && (
                    <>
                        <RNView style={styles.iconContainer}>
                            <Ionicons name="key-outline" size={48} color={p.blue} />
                        </RNView>
                        <Text style={styles.title}>{t('recover.enterCodeTitle')}</Text>
                        <Text style={styles.subtitle}>{t('recover.enterCodeBody')}</Text>

                        <RNView style={styles.card}>
                            <Text style={styles.fieldLabel}>{t('recover.recoveryPhrase')}</Text>
                            <TextInput
                                style={[styles.input, { minHeight: 100, textAlignVertical: 'top' }]}
                                value={codeInput}
                                onChangeText={setCodeInput}
                                placeholder={t('recover.phrasePlaceholder')}
                                placeholderTextColor={p.textMuted}
                                autoCapitalize="none"
                                autoCorrect={false}
                                autoFocus
                                multiline
                            />
                            {/* Live word-by-word validation: green = recovery
                                word, red = not one (check your transcription),
                                grey = still being typed. */}
                            {wordStates.length > 0 && (
                                <>
                                    <RNView style={styles.wordChips}>
                                        {wordStates.map(({ w, state }, i) => (
                                            <RNView
                                                key={`${i}-${w}`}
                                                style={[
                                                    styles.wordChip,
                                                    state === 'valid' && styles.wordChipValid,
                                                    state === 'invalid' && styles.wordChipInvalid,
                                                ]}
                                            >
                                                <Text
                                                    style={[
                                                        styles.wordChipText,
                                                        state === 'invalid' && styles.wordChipTextInvalid,
                                                    ]}
                                                >
                                                    {i + 1}. {w}
                                                </Text>
                                            </RNView>
                                        ))}
                                    </RNView>
                                    <Text
                                        style={[
                                            styles.wordCount,
                                            wordStates.length === 24 &&
                                                wordStates.every((s) => s.state === 'valid') &&
                                                styles.wordCountComplete,
                                        ]}
                                    >
                                        {t('recover.wordProgress', { count: wordStates.length })}
                                        {wordStates.some((s) => s.state === 'invalid')
                                            ? t('recover.fixRedWords')
                                            : ''}
                                    </Text>
                                </>
                            )}
                            <Pressable
                                style={[styles.primaryButton, (submitting || !codeInput.trim()) && { opacity: 0.6 }]}
                                onPress={handleSubmitCode}
                                disabled={submitting || !codeInput.trim()}
                            >
                                {submitting ? (
                                    <ActivityIndicator color="#FFFFFF" size="small" />
                                ) : (
                                    <Text style={styles.primaryButtonText}>{t('recover.begin')}</Text>
                                )}
                            </Pressable>
                        </RNView>
                    </>
                )}

                {/* Step 2: Waiting for guardians */}
                {step === 'waiting' && recoveryState && (
                    <>
                        <RNView style={styles.iconContainer}>
                            <ActivityIndicator color={p.blue} size="large" />
                        </RNView>
                        <Text style={styles.title}>{t('recover.waitingTitle')}</Text>
                        <Text style={styles.subtitle}>{t('recover.waitingBody')}</Text>

                        <RNView style={styles.card}>
                            <RNView style={styles.progressRow}>
                                <Text style={styles.progressLabel}>{t('recover.guardianApprovals')}</Text>
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
                                {t('recover.expiresAt', { when: new Date(recoveryState.expiresAt) })}
                            </Text>
                        </RNView>

                        <Pressable style={styles.secondaryButton} onPress={handleCancel}>
                            <Text style={[styles.secondaryButtonText, { color: p.danger }]}>
                                {t('recover.cancelTitle')}
                            </Text>
                        </Pressable>
                    </>
                )}

                {/* Step 3: Approved — complete recovery */}
                {step === 'approved' && recoveryState && (
                    <>
                        <RNView style={styles.iconContainer}>
                            <Ionicons name="checkmark-circle" size={48} color={p.green} />
                        </RNView>
                        <Text style={styles.title}>{t('recover.approvedTitle')}</Text>
                        <Text style={styles.subtitle}>{t('recover.approvedBody')}</Text>

                        {completeError ? (
                            <Pressable
                                style={[styles.primaryButton, completing && { opacity: 0.6 }]}
                                onPress={handleComplete}
                                disabled={completing}
                            >
                                {completing ? (
                                    <ActivityIndicator color="#FFFFFF" size="small" />
                                ) : (
                                    <Text style={styles.primaryButtonText}>{t('recover.retry')}</Text>
                                )}
                            </Pressable>
                        ) : (
                            <RNView style={styles.finalisingRow}>
                                <ActivityIndicator color={p.blue} size="small" />
                                <Text style={styles.finalisingText}>{t('recover.finalising')}</Text>
                            </RNView>
                        )}
                    </>
                )}

                {/* Step 4: Completed — the account is unlocked server-side; now
                    bind THIS device to it. Without this step the recovery is
                    incomplete: the old credentials were just revoked and
                    nothing signs for the account yet. */}
                {step === 'completed' && (
                    <>
                        <RNView style={styles.iconContainer}>
                            <Ionicons name="shield-checkmark" size={48} color={p.green} />
                        </RNView>
                        <Text style={styles.title}>{t('recover.recoveredTitle')}</Text>
                        <Text style={styles.subtitle}>{t('recover.recoveredBody')}</Text>

                        <Pressable
                            style={[styles.primaryButton, registering && { opacity: 0.6 }]}
                            onPress={handleRegisterRecovered}
                            disabled={registering}
                        >
                            {registering ? (
                                <ActivityIndicator color="#FFFFFF" />
                            ) : (
                                <Text style={styles.primaryButtonText}>{t('recover.registerDevice')}</Text>
                            )}
                        </Pressable>
                    </>
                )}

                {/* Step 5: Restored — device bound to the recovered account. */}
                {step === 'restored' && (
                    <>
                        <RNView style={styles.iconContainer}>
                            <Ionicons name="checkmark-circle" size={48} color={p.green} />
                        </RNView>
                        <Text style={styles.title}>{t('recover.restoredTitle')}</Text>
                        <Text style={styles.subtitle}>{t('recover.restoredBody')}</Text>

                        <Pressable style={styles.primaryButton} onPress={handleDismiss}>
                            <Text style={styles.primaryButtonText}>{t('common.done')}</Text>
                        </Pressable>
                    </>
                )}

                {/* Expired */}
                {step === 'expired' && (
                    <>
                        <RNView style={styles.iconContainer}>
                            <Ionicons name="time-outline" size={48} color="#F59E0B" />
                        </RNView>
                        <Text style={styles.title}>{t('recover.expiredTitle')}</Text>
                        <Text style={styles.subtitle}>{t('recover.expiredBody')}</Text>

                        <Pressable
                            style={styles.primaryButton}
                            onPress={() => {
                                setRecoveryState(null);
                                setStep('enter-code');
                            }}
                        >
                            <Text style={styles.primaryButtonText}>{t('common.retry')}</Text>
                        </Pressable>
                    </>
                )}

                <RNView style={{ height: 40 }} />
            </ScrollView>
            </KeyboardAvoidingView>
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

    iconContainer: {
        alignItems: 'center',
        marginTop: 40,
        marginBottom: 20,
    },
    title: {
        fontSize: 22,
        fontWeight: '700',
        color: p.textPrimary,
        textAlign: 'center',
        marginBottom: 8,
    },
    subtitle: {
        fontSize: 15,
        color: p.textSecondary,
        textAlign: 'center',
        lineHeight: 22,
        marginBottom: 24,
        paddingHorizontal: 8,
    },

    card: {
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 16,
        marginBottom: 16,
    },
    fieldLabel: {
        fontSize: 12,
        fontWeight: '600',
        color: p.textMuted,
        marginBottom: 6,
        textTransform: 'uppercase',
        letterSpacing: 0.3,
    },
    input: {
        backgroundColor: p.cardAlt,
        borderRadius: 10,
        paddingHorizontal: 14,
        paddingVertical: 12,
        fontSize: 16,
        color: p.textPrimary,
        marginBottom: 12,
        fontFamily: 'Inter',
        letterSpacing: 1,
    },

    wordChips: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        gap: 6,
        marginBottom: 8,
    },
    wordChip: {
        paddingHorizontal: 8,
        paddingVertical: 4,
        borderRadius: 6,
        backgroundColor: p.cardAlt,
        borderWidth: 1,
        borderColor: p.border,
    },
    wordChipValid: {
        backgroundColor: p.successBg,
        borderColor: p.successBorder,
    },
    wordChipInvalid: {
        backgroundColor: p.dangerBg,
        borderColor: p.dangerBorder,
    },
    wordChipText: {
        fontSize: 12,
        fontFamily: 'Inter',
        color: p.textPrimary,
    },
    wordChipTextInvalid: {
        color: p.dangerText,
        fontWeight: '600',
    },
    wordCount: {
        fontSize: 12,
        color: p.textMuted,
        marginBottom: 12,
        textAlign: 'right',
    },
    wordCountComplete: {
        color: p.infoText,
        fontWeight: '600',
    },

    primaryButton: {
        backgroundColor: p.blue,
        borderRadius: 10,
        paddingVertical: 14,
        alignItems: 'center' as const,
    },
    primaryButtonText: {
        color: '#FFFFFF',
        fontSize: 16,
        fontWeight: '600',
    },
    finalisingRow: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        marginTop: 8,
    },
    finalisingText: {
        color: p.textSecondary,
        fontSize: 15,
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
        color: p.textSecondary,
        fontWeight: '500',
    },
    progressValue: {
        fontSize: 16,
        color: p.textPrimary,
        fontWeight: '700',
    },
    progressBar: {
        height: 8,
        backgroundColor: p.border,
        borderRadius: 4,
        overflow: 'hidden',
        marginBottom: 12,
    },
    progressFill: {
        height: '100%',
        backgroundColor: p.green,
        borderRadius: 4,
    },
    expiresText: {
        fontSize: 12,
        color: p.textMuted,
        textAlign: 'center',
    },
});
