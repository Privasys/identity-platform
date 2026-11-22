// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The new device's side of adding a device: show a QR code for the holder's
 * other device to scan, wait for what it sends, ask the holder to type the six
 * digits that device shows, then become the same wallet and say it is ready
 * (services/device-flows).
 *
 * Typing rather than comparing: what arrived opens with this device's key, so
 * only this device can read it; the code shows it came from the holder's own
 * device and not from someone who saw the QR code. People tap "they match"
 * without looking; nobody types a code they have not read.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, TextInput, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { QrCode } from '@/components/QrCode';
import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import {
    installTransfer,
    openPairing,
    waitForTransfer,
    type InstallProgress,
    type PairingSession,
    type ReceivedTransfer,
} from '@/services/device-flows';
import { pairingLink, sameCode } from '@/services/devices';
import { useLargeScreen } from '@/hooks/useLargeScreen';

type Phase = 'opening' | 'showing' | 'expired' | 'enter' | 'installing' | 'done' | 'failed';

export default function DeviceAddScreen() {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const router = useRouter();

    const [phase, setPhase] = useState<Phase>('opening');
    const [session, setSession] = useState<PairingSession | null>(null);
    const [received, setReceived] = useState<ReceivedTransfer | null>(null);
    const [progress, setProgress] = useState<InstallProgress | null>(null);
    const [problem, setProblem] = useState('');
    const [typed, setTyped] = useState('');
    const [wrong, setWrong] = useState(false);
    const large = useLargeScreen();
    const abort = useRef({ aborted: false });

    const start = useCallback(async () => {
        abort.current.aborted = true;
        const signal = { aborted: false };
        abort.current = signal;
        setPhase('opening');
        setProblem('');
        try {
            const s = await openPairing();
            if (signal.aborted) return;
            setSession(s);
            setPhase('showing');
            const r = await waitForTransfer(s, signal);
            if (signal.aborted) return;
            setReceived(r);
            setTyped('');
            setWrong(false);
            setPhase('enter');
        } catch (e: any) {
            if (signal.aborted) return;
            if (e?.reason === 'expired') {
                setPhase('expired');
            } else {
                setProblem(e?.message ?? String(e));
                setPhase('failed');
            }
        }
    }, []);

    useEffect(() => {
        void start();
        return () => {
            abort.current.aborted = true;
        };
    }, [start]);

    const install = async () => {
        if (!received) return;
        // A wrong code installs nothing: what arrived may not be the holder's.
        if (!sameCode(typed, received.code)) {
            setWrong(true);
            return;
        }
        setPhase('installing');
        try {
            const r = await installTransfer(received, setProgress);
            setProgress(r);
            setPhase('done');
        } catch (e: any) {
            setProblem(e?.message ?? String(e));
            setPhase('failed');
        }
    };

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('devices.addTitle')} />
            <ScrollView contentContainerStyle={[styles.body, { paddingBottom: insets.bottom + 32 }]}>
                {phase === 'opening' && <ActivityIndicator style={styles.spinner} color={p.blue} />}

                {phase === 'showing' && session && (
                    <>
                        <Text style={styles.lede}>{t('devices.addLede')}</Text>
                        <RNView style={styles.qrWrap}>
                            <QrCode value={pairingLink(session.slot, session.publicKey)} size={large ? 320 : 240} />
                        </RNView>
                        <RNView style={styles.waiting}>
                            <ActivityIndicator color={p.textMuted} />
                            <Text style={styles.waitingText}>{t('devices.addWaiting')}</Text>
                        </RNView>
                    </>
                )}

                {phase === 'expired' && (
                    <>
                        <Text style={styles.lede}>{t('devices.addExpired')}</Text>
                        <Pressable style={styles.primary} onPress={() => void start()}>
                            <Text style={styles.primaryText}>{t('devices.addAgain')}</Text>
                        </Pressable>
                    </>
                )}

                {phase === 'enter' && received && (
                    <>
                        <Text style={styles.title}>{t('devices.enterTitle', { from: received.from })}</Text>
                        <TextInput
                            style={[styles.codeInput, wrong && styles.codeInputWrong]}
                            value={typed}
                            onChangeText={(v) => {
                                setTyped(v.replace(/[^\d ]/g, '').slice(0, 7));
                                setWrong(false);
                            }}
                            onSubmitEditing={() => void install()}
                            keyboardType="number-pad"
                            textContentType="oneTimeCode"
                            autoFocus
                            maxLength={7}
                            placeholder="000 000"
                            placeholderTextColor={p.textMuted}
                            accessibilityLabel={t('devices.enterTitle', { from: received.from })}
                            testID="device-add-code"
                        />
                        {wrong ? <Text style={styles.problem}>{t('devices.enterWrong', { from: received.from })}</Text> : null}
                        <Text style={styles.why}>{t('devices.enterWhy')}</Text>
                        <Pressable
                            style={[styles.primary, digitsOf(typed).length !== 6 && styles.disabled]}
                            disabled={digitsOf(typed).length !== 6}
                            onPress={() => void install()}
                        >
                            <Text style={styles.primaryText}>{t('common.continue')}</Text>
                        </Pressable>
                    </>
                )}

                {phase === 'installing' && (
                    <RNView style={styles.doneWrap}>
                        <ActivityIndicator color={p.blue} />
                        <Text style={[styles.title, styles.spaced]}>
                            {progress && progress.identities > 0
                                ? t('devices.installingIdentities', {
                                      done: progress.done + progress.failed,
                                      total: progress.identities,
                                  })
                                : t('devices.installing')}
                        </Text>
                        <Text style={[styles.lede, styles.centred]}>{t('devices.installingBody')}</Text>
                    </RNView>
                )}

                {phase === 'done' && (
                    <RNView style={styles.doneWrap}>
                        <RNView style={styles.doneIcon}>
                            <Ionicons name="checkmark" size={34} color="#FFFFFF" />
                        </RNView>
                        <Text style={styles.title}>{t('devices.doneTitle')}</Text>
                        <Text style={[styles.lede, styles.centred]}>{t('devices.doneBody')}</Text>
                        {progress && progress.failed > 0 ? (
                            <Text style={styles.note}>{t('devices.doneSome', { count: progress.failed })}</Text>
                        ) : null}
                        <Pressable style={[styles.primary, styles.stretch]} onPress={() => router.replace('/(tabs)')}>
                            <Text style={styles.primaryText}>{t('devices.doneOpen')}</Text>
                        </Pressable>
                    </RNView>
                )}

                {phase === 'failed' && (
                    <>
                        <Text style={styles.problem}>{t('devices.addFailed', { reason: problem })}</Text>
                        <Pressable style={styles.primary} onPress={() => void start()}>
                            <Text style={styles.primaryText}>{t('devices.addAgain')}</Text>
                        </Pressable>
                    </>
                )}
            </ScrollView>
        </RNView>
    );
}

/** A typed code's digits, whatever spacing the holder used. */
function digitsOf(s: string): string {
    return s.replace(/\D/g, '');
}

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        screen: { flex: 1, backgroundColor: p.screenBg },
        body: { padding: 24, paddingTop: 28 },
        spinner: { marginTop: 48 },
        title: { fontSize: 22, fontWeight: '700', color: p.textPrimary, marginBottom: 8, textAlign: 'center' },
        lede: { fontSize: 15, lineHeight: 22, color: p.textSecondary },
        qrWrap: {
            marginTop: 24,
            alignSelf: 'center',
            padding: 16,
            backgroundColor: '#FFFFFF',
            borderRadius: 16,
        },
        waiting: { marginTop: 24, flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 10 },
        waitingText: { fontSize: 14, color: p.textMuted },
        codeInput: {
            marginTop: 20,
            alignSelf: 'center',
            minWidth: 240,
            paddingVertical: 14,
            paddingHorizontal: 20,
            borderRadius: 14,
            borderWidth: 1.5,
            borderColor: p.border,
            backgroundColor: p.card,
            fontSize: 34,
            fontWeight: '700',
            letterSpacing: 6,
            textAlign: 'center',
            color: p.textPrimary,
            fontVariant: ['tabular-nums'],
        },
        codeInputWrong: { borderColor: p.danger },
        why: {
            marginTop: 20,
            padding: 14,
            borderRadius: 12,
            backgroundColor: p.card,
            fontSize: 14,
            lineHeight: 20,
            color: p.textSecondary,
        },
        disabled: { opacity: 0.5 },
        spaced: { marginTop: 16 },
        centred: { textAlign: 'center' },
        primary: {
            marginTop: 24,
            backgroundColor: p.action,
            borderRadius: 14,
            paddingVertical: 16,
            paddingHorizontal: 20,
            alignItems: 'center',
        },
        primaryText: { color: '#FFFFFF', fontSize: 16, fontWeight: '600' },
        secondary: { marginTop: 14, paddingVertical: 10, alignItems: 'center' },
        secondaryText: { color: p.danger, fontSize: 15, fontWeight: '600' },
        problem: { marginTop: 12, fontSize: 15, lineHeight: 22, color: p.danger, textAlign: 'center' },
        note: { marginTop: 12, fontSize: 13, lineHeight: 19, color: p.textMuted, textAlign: 'center' },
        doneWrap: { alignItems: 'center', paddingTop: 24 },
        doneIcon: {
            width: 64,
            height: 64,
            borderRadius: 32,
            backgroundColor: p.green,
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: 20,
        },
        stretch: { alignSelf: 'stretch' },
    });
