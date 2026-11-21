// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Prove an address the holder typed: privasys.id mails a code, they type it
 * back, and the attribute stops being something they merely claimed.
 *
 * An address that came from a provider which says it checked it arrives
 * verified already, so this screen is only ever reached for one nobody has
 * checked. It writes the receipt privasys.id signs onto the attribute as
 * evidence, and leaves the address itself where it has always been: here.
 */

import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
    ActivityIndicator,
    KeyboardAvoidingView,
    Platform,
    Pressable,
    ScrollView,
    StyleSheet,
    TextInput,
    View as RNView,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import {
    confirmEmailCode,
    sendEmailCode,
    EmailVerifyError,
    type EmailVerifyFailure,
} from '@/services/email-verification';
import { thisDeviceBinding } from '@/services/attribute-proofs';
import { notify, useNoticeStore } from '@/stores/notice';
import { useProfileStore } from '@/stores/profile';

type Phase = 'ready' | 'sending' | 'entering' | 'checking';

/** What to say for each way this can fail. */
function failureKey(reason: EmailVerifyFailure): string {
    switch (reason) {
        case 'bad-address':
            return 'verifyEmail.errorAddress';
        case 'wrong-code':
            return 'verifyEmail.errorWrongCode';
        case 'expired':
            return 'verifyEmail.errorExpired';
        case 'too-soon':
            return 'verifyEmail.errorTooSoon';
        case 'no-mail':
            return 'verifyEmail.errorNoMail';
        case 'offline':
            return 'verifyEmail.errorOffline';
        default:
            return 'verifyEmail.errorSend';
    }
}

export default function VerifyEmailScreen() {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const params = useLocalSearchParams<{ email?: string }>();
    const address = String(params.email ?? '').trim();

    const [phase, setPhase] = useState<Phase>('ready');
    const [code, setCode] = useState('');
    const [problem, setProblem] = useState('');
    const [codeLength, setCodeLength] = useState(6);
    /** Seconds until another code may be asked for; 0 = now. */
    const [wait, setWait] = useState(0);
    const inputRef = useRef<TextInput>(null);

    useEffect(() => {
        if (wait <= 0) return;
        const id = setInterval(() => setWait((s) => (s <= 1 ? 0 : s - 1)), 1000);
        return () => clearInterval(id);
    }, [wait]);

    const send = useCallback(async () => {
        setProblem('');
        setPhase('sending');
        try {
            const sent = await sendEmailCode(address);
            setCodeLength(sent.codeLength);
            setWait(sent.resendAfter);
            setCode('');
            setPhase('entering');
            setTimeout(() => inputRef.current?.focus(), 250);
        } catch (e) {
            if (e instanceof EmailVerifyError) {
                setProblem(t(failureKey(e.reason)));
                if (e.reason === 'too-soon') {
                    setWait(e.retryAfter ?? 60);
                    setPhase('entering');
                    return;
                }
            } else {
                setProblem(t('verifyEmail.errorSend'));
            }
            setPhase('ready');
        }
    }, [address, t]);

    const confirm = useCallback(async () => {
        setProblem('');
        setPhase('checking');
        try {
            const result = await confirmEmailCode(address, code);
            // The address as the verifier normalised it, so what is stored is
            // what the proof attests. The proof is kept on the attribute and
            // disclosed afresh to an app at sign-in (services/attribute-proofs).
            const device = await thisDeviceBinding();
            useProfileStore.getState().updateAttributeValue('email', address, {
                value: result.email,
                verified: true,
                verifications: [
                    {
                        verifier: result.proof.source,
                        verifierDisplayName: 'Privasys',
                        method: 'email_code',
                        assurance: 'provider',
                        verifiedAt: result.verifiedAt,
                        evidence: `verifier:${result.proof.source}:${result.proof.method}`,
                        proof: result.proof.proof,
                        proofDevice: device,
                        proofSalt: result.salt,
                    },
                ],
            });
            // The profile's own email field follows the attribute it mirrors.
            const profile = useProfileStore.getState().profile;
            if (profile && profile.email.toLowerCase() === address.toLowerCase()) {
                useProfileStore.getState().updateProfile({ email: result.email });
            }
            // No page to say it worked: back to where the check was asked for
            // (personal data, or a sign-in waiting on it), the address picked out
            // there and the message strip saying so.
            useNoticeStore.getState().markFresh([{ key: 'email', value: result.email }]);
            notify(t('verifyEmail.doneTitle'), t('verifyEmail.doneBody', { email: result.email }));
            router.back();
        } catch (e) {
            if (e instanceof EmailVerifyError) {
                const left = e.attemptsLeft;
                setProblem(
                    left !== undefined && left > 0
                        ? `${t('verifyEmail.errorWrongCode')} ${t('verifyEmail.triesLeft', { tries: left })}`
                        : t(failureKey(e.reason)),
                );
                // Out of tries, expired or already used: the only way on is a
                // new code, so the screen goes back to offering one.
                setPhase(e.reason === 'expired' ? 'ready' : 'entering');
                if (e.reason === 'expired') setCode('');
                return;
            }
            setProblem(t('verifyEmail.errorSend'));
            setPhase('entering');
        }
    }, [address, code, router, t]);

    if (!address) {
        return (
            <RNView style={styles.screen}>
                <SubPageHeader title={t('verifyEmail.title')} />
                <RNView style={styles.body}>
                    <Text style={styles.problem}>{t('verifyEmail.errorAddress')}</Text>
                </RNView>
            </RNView>
        );
    }

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('verifyEmail.title')} />
            <KeyboardAvoidingView
                style={{ flex: 1 }}
                behavior={Platform.OS === 'ios' ? 'padding' : undefined}
                keyboardVerticalOffset={0}
            >
                <ScrollView
                    contentContainerStyle={[styles.body, { paddingBottom: insets.bottom + 48 }]}
                    keyboardShouldPersistTaps="handled"
                    showsVerticalScrollIndicator={false}
                >
                    {(
                        <>
                            <Text style={styles.address}>{address}</Text>
                            <Text style={styles.lede}>
                                {phase === 'entering' || phase === 'checking'
                                    ? t('verifyEmail.ledeSent')
                                    : t('verifyEmail.lede')}
                            </Text>

                            {(phase === 'entering' || phase === 'checking') && (
                                <TextInput
                                    ref={inputRef}
                                    style={styles.code}
                                    value={code}
                                    onChangeText={(v) => setCode(v.replace(/[^0-9]/g, '').slice(0, codeLength))}
                                    keyboardType="number-pad"
                                    textContentType="oneTimeCode"
                                    autoComplete="one-time-code"
                                    maxLength={codeLength}
                                    placeholder={'0'.repeat(codeLength)}
                                    placeholderTextColor={p.textMuted}
                                    editable={phase === 'entering'}
                                    accessibilityLabel={t('verifyEmail.codeLabel')}
                                />
                            )}

                            {problem ? <Text style={styles.problem}>{problem}</Text> : null}

                            {phase === 'entering' || phase === 'checking' ? (
                                <>
                                    <Pressable
                                        style={[
                                            styles.primary,
                                            (code.length < codeLength || phase === 'checking') && styles.disabled,
                                        ]}
                                        disabled={code.length < codeLength || phase === 'checking'}
                                        onPress={() => void confirm()}
                                    >
                                        {phase === 'checking' ? (
                                            <ActivityIndicator color="#FFFFFF" />
                                        ) : (
                                            <Text style={styles.primaryText}>{t('verifyEmail.confirm')}</Text>
                                        )}
                                    </Pressable>
                                    <Pressable
                                        style={styles.secondary}
                                        disabled={wait > 0 || phase === 'checking'}
                                        onPress={() => void send()}
                                    >
                                        <Text style={[styles.secondaryText, wait > 0 && styles.secondaryWaiting]}>
                                            {wait > 0
                                                ? t('verifyEmail.resendIn', { seconds: wait })
                                                : t('verifyEmail.resend')}
                                        </Text>
                                    </Pressable>
                                </>
                            ) : (
                                <Pressable
                                    style={[styles.primary, phase === 'sending' && styles.disabled]}
                                    disabled={phase === 'sending'}
                                    onPress={() => void send()}
                                >
                                    {phase === 'sending' ? (
                                        <ActivityIndicator color="#FFFFFF" />
                                    ) : (
                                        <Text style={styles.primaryText}>{t('verifyEmail.send')}</Text>
                                    )}
                                </Pressable>
                            )}

                            <Text style={styles.note}>{t('verifyEmail.note')}</Text>
                        </>
                    )}
                </ScrollView>
            </KeyboardAvoidingView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    body: { padding: 24, paddingTop: 28 },
    address: { fontSize: 20, fontWeight: '700', color: p.textPrimary, marginBottom: 8 },
    lede: { fontSize: 15, lineHeight: 22, color: p.textSecondary },
    code: {
        marginTop: 24,
        backgroundColor: p.card,
        borderRadius: 14,
        borderWidth: 1,
        borderColor: p.border,
        paddingVertical: 16,
        fontSize: 28,
        fontWeight: '700',
        letterSpacing: 10,
        textAlign: 'center',
        color: p.textPrimary,
    },
    problem: { marginTop: 16, fontSize: 14, lineHeight: 20, color: p.danger },
    primary: {
        marginTop: 24,
        backgroundColor: p.action,
        borderRadius: 14,
        paddingVertical: 16,
        alignItems: 'center',
    },
    primaryText: { color: '#FFFFFF', fontSize: 16, fontWeight: '600' },
    disabled: { opacity: 0.5 },
    secondary: { marginTop: 14, paddingVertical: 10, alignItems: 'center' },
    secondaryText: { color: p.blue, fontSize: 15, fontWeight: '600' },
    secondaryWaiting: { color: p.textMuted },
    note: { marginTop: 28, fontSize: 12.5, lineHeight: 19, color: p.textMuted },
});
