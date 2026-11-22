// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The sending device's side of adding a device, reached by scanning the QR
 * code the new device shows (with the Camera or in the wallet). It says what
 * it will send and how: sealed on this device for the new one only. Continue
 * asks for the holder's biometric and sends. It then shows the six digits the
 * holder types on the new device, with nothing to press: it closes by itself
 * once the new device has finished, and Close is always there to leave sooner
 * (services/device-flows).
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useMemo, useRef, useState } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { DeviceError, sendToNewPhone, waitForNewDevice, type SentTransfer } from '@/services/device-flows';
import { MAX_DEVICES } from '@/services/devices';
import { notify } from '@/stores/notice';

type Phase = 'ready' | 'sending' | 'sent' | 'failed';

/** What goes across, as the holder knows it (services/device-flows, Transfer). */
const ITEMS: { icon: keyof typeof Ionicons.glyphMap; key: string }[] = [
    { icon: 'person-outline', key: 'devices.sendItemDetails' },
    { icon: 'apps-outline', key: 'devices.sendItemSignIns' },
    { icon: 'key-outline', key: 'devices.sendItemPasskeys' },
    { icon: 'shield-checkmark-outline', key: 'devices.sendItemKeys' },
];

export default function DeviceSendScreen() {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const params = useLocalSearchParams<{ s?: string; k?: string }>();
    const slot = String(params.s ?? '');
    const key = String(params.k ?? '');

    const [phase, setPhase] = useState<Phase>('ready');
    const [sent, setSent] = useState<SentTransfer | null>(null);
    const [problem, setProblem] = useState('');
    const watching = useRef({ aborted: false });

    const leave = () => (router.canGoBack() ? router.back() : router.replace('/(tabs)'));

    // Sent: close by itself once the new device has finished.
    useEffect(() => {
        if (!sent) return;
        const signal = { aborted: false };
        watching.current = signal;
        void waitForNewDevice(sent, signal).then((name) => {
            if (signal.aborted || !name) return;
            notify(t('devices.sendReadyTitle'), t('devices.sendReadyBody', { name }));
            router.replace('/(tabs)');
        });
        return () => {
            signal.aborted = true;
        };
    }, [sent, router, t]);

    const send = async () => {
        setPhase('sending');
        setProblem('');
        try {
            setSent(await sendToNewPhone({ slot, key }));
            setPhase('sent');
        } catch (e: any) {
            const reason = e instanceof DeviceError ? e.reason : '';
            setProblem(
                reason === 'limit'
                    ? t('devices.sendLimit', { max: MAX_DEVICES })
                    : reason === 'expired'
                      ? t('devices.sendExpired')
                      : reason === 'used'
                        ? t('devices.sendUsed')
                        : t('devices.sendFailed', { reason: e?.message ?? String(e) }),
            );
            setPhase('failed');
        }
    };

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('devices.sendTitle')} />
            <ScrollView contentContainerStyle={[styles.body, { paddingBottom: insets.bottom + 32 }]}>
                {phase === 'sent' && sent ? (
                    <RNView style={styles.center}>
                        <Text style={styles.title}>{t('devices.sendCodeTitle')}</Text>
                        <RNView style={styles.codeCard}>
                            <Text style={styles.code} accessibilityLabel={sent.code}>
                                {sent.code}
                            </Text>
                        </RNView>
                        <Text style={[styles.lede, styles.centred]}>{t('devices.sendCodeBody')}</Text>
                        <RNView style={styles.waiting}>
                            <ActivityIndicator color={p.textMuted} />
                            <Text style={styles.waitingText}>{t('devices.sendWaiting')}</Text>
                        </RNView>
                        <Pressable style={[styles.plainButton, styles.stretch]} onPress={leave} testID="device-send-close">
                            <Text style={styles.plainButtonText}>{t('common.close')}</Text>
                        </Pressable>
                    </RNView>
                ) : (
                    <>
                        <Text style={styles.lede}>{t('devices.sendLede')}</Text>
                        <RNView style={styles.card}>
                            {ITEMS.map((it) => (
                                <RNView key={it.key} style={styles.item}>
                                    <RNView style={styles.itemIcon}>
                                        <Ionicons name={it.icon} size={16} color={p.action} />
                                    </RNView>
                                    <Text style={styles.itemText}>{t(it.key)}</Text>
                                </RNView>
                            ))}
                        </RNView>
                        <RNView style={styles.note}>
                            <Ionicons name="lock-closed" size={16} color={p.textSecondary} />
                            <Text style={styles.noteText}>{t('devices.sendSealed')}</Text>
                        </RNView>
                        {problem ? <Text style={styles.problem}>{problem}</Text> : null}
                        <Pressable
                            style={[styles.primary, phase === 'sending' && styles.disabled]}
                            disabled={phase === 'sending' || !slot || !key}
                            onPress={() => void send()}
                            testID="device-send-continue"
                        >
                            {phase === 'sending' ? (
                                <ActivityIndicator color="#FFFFFF" />
                            ) : (
                                <Text style={styles.primaryText}>{t('devices.sendConfirm')}</Text>
                            )}
                        </Pressable>
                        <Pressable style={styles.secondary} onPress={leave}>
                            <Text style={styles.secondaryText}>{t('common.cancel')}</Text>
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
        center: { alignItems: 'center' },
        title: { fontSize: 22, fontWeight: '700', color: p.textPrimary, marginBottom: 8, textAlign: 'center' },
        lede: { fontSize: 15, lineHeight: 22, color: p.textSecondary },
        centred: { textAlign: 'center' },
        card: { marginTop: 16, padding: 16, gap: 12, borderRadius: 14, backgroundColor: p.card },
        item: { flexDirection: 'row', alignItems: 'center', gap: 12 },
        itemIcon: {
            width: 30,
            height: 30,
            borderRadius: 8,
            backgroundColor: `${p.action}14`,
            alignItems: 'center',
            justifyContent: 'center',
        },
        itemText: { flex: 1, fontSize: 15, color: p.textPrimary },
        note: { marginTop: 14, flexDirection: 'row', gap: 10, alignItems: 'flex-start', paddingHorizontal: 4 },
        noteText: { flex: 1, fontSize: 14, lineHeight: 20, color: p.textSecondary },
        codeCard: { marginVertical: 20, paddingVertical: 16, paddingHorizontal: 28, borderRadius: 14, backgroundColor: p.card },
        code: {
            fontSize: 40,
            fontWeight: '700',
            letterSpacing: 6,
            textAlign: 'center',
            color: p.textPrimary,
            fontVariant: ['tabular-nums'],
        },
        waiting: { marginTop: 24, flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 10 },
        waitingText: { fontSize: 14, color: p.textMuted },
        problem: { marginTop: 16, fontSize: 14, lineHeight: 20, color: p.danger },
        primary: {
            marginTop: 24,
            backgroundColor: p.action,
            borderRadius: 14,
            paddingVertical: 16,
            paddingHorizontal: 20,
            alignItems: 'center',
        },
        primaryText: { color: '#FFFFFF', fontSize: 16, fontWeight: '600' },
        disabled: { opacity: 0.5 },
        plainButton: {
            marginTop: 24,
            backgroundColor: p.card,
            borderRadius: 14,
            paddingVertical: 16,
            alignItems: 'center',
        },
        plainButtonText: { color: p.textPrimary, fontSize: 16, fontWeight: '600' },
        secondary: { marginTop: 14, paddingVertical: 10, alignItems: 'center' },
        secondaryText: { color: p.blue, fontSize: 15, fontWeight: '600' },
        stretch: { alignSelf: 'stretch' },
    });
