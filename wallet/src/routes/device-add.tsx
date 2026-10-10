// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The new phone's side of adding a phone: show a code for the holder's other
 * phone to scan, wait for what it sends, let the holder check that both phones
 * show the same six digits, then become the same wallet (services/device-flows).
 */

import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
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
import { pairingLink } from '@/services/devices';

type Phase = 'opening' | 'showing' | 'expired' | 'checking' | 'installing' | 'done' | 'failed';

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
            setPhase('checking');
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
                            <QrCode value={pairingLink(session.slot, session.publicKey)} size={240} />
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

                {phase === 'checking' && received && (
                    <>
                        <Text style={styles.title}>{t('devices.checkTitle')}</Text>
                        <Text style={styles.lede}>{t('devices.checkBody', { from: received.from })}</Text>
                        <Text style={styles.code} accessibilityLabel={received.code}>
                            {received.code}
                        </Text>
                        <Pressable style={styles.primary} onPress={() => void install()}>
                            <Text style={styles.primaryText}>{t('devices.checkMatch')}</Text>
                        </Pressable>
                        <Pressable
                            style={styles.secondary}
                            onPress={() => {
                                setReceived(null);
                                void start();
                            }}
                        >
                            <Text style={styles.secondaryText}>{t('devices.checkNoMatch')}</Text>
                        </Pressable>
                    </>
                )}

                {phase === 'installing' && (
                    <RNView style={styles.waiting}>
                        <ActivityIndicator color={p.blue} />
                        <Text style={styles.waitingText}>
                            {progress && progress.identities > 0
                                ? t('devices.installingIdentities', {
                                      done: progress.done + progress.failed,
                                      total: progress.identities,
                                  })
                                : t('devices.installing')}
                        </Text>
                    </RNView>
                )}

                {phase === 'done' && (
                    <RNView style={styles.doneWrap}>
                        <RNView style={styles.doneIcon}>
                            <Ionicons name="checkmark" size={34} color="#FFFFFF" />
                        </RNView>
                        <Text style={styles.title}>{t('devices.doneTitle')}</Text>
                        <Text style={styles.lede}>{t('devices.doneBody')}</Text>
                        {progress && progress.failed > 0 ? (
                            <Text style={styles.note}>{t('devices.doneSome', { count: progress.failed })}</Text>
                        ) : null}
                        <Pressable style={[styles.primary, styles.stretch]} onPress={() => router.replace('/(tabs)')}>
                            <Text style={styles.primaryText}>{t('common.done')}</Text>
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
        code: {
            marginTop: 24,
            fontSize: 40,
            fontWeight: '700',
            letterSpacing: 6,
            textAlign: 'center',
            color: p.textPrimary,
            fontVariant: ['tabular-nums'],
        },
        primary: {
            marginTop: 24,
            backgroundColor: p.blue,
            borderRadius: 14,
            paddingVertical: 16,
            paddingHorizontal: 20,
            alignItems: 'center',
        },
        primaryText: { color: '#FFFFFF', fontSize: 16, fontWeight: '600' },
        secondary: { marginTop: 14, paddingVertical: 10, alignItems: 'center' },
        secondaryText: { color: p.danger, fontSize: 15, fontWeight: '600' },
        problem: { fontSize: 15, lineHeight: 22, color: p.danger },
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
