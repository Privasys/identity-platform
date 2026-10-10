// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The old phone's side of adding a phone, reached by scanning the code the new
 * phone shows: say what will be sent, send it on the holder's Face ID, then show
 * the six digits the new phone must show too (services/device-flows).
 */

import { Ionicons } from '@expo/vector-icons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useMemo, useState } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { DeviceError, sendToNewPhone } from '@/services/device-flows';
import { MAX_DEVICES } from '@/services/devices';

type Phase = 'ready' | 'sending' | 'sent' | 'failed';

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
    const [code, setCode] = useState('');
    const [problem, setProblem] = useState('');

    const send = async () => {
        setPhase('sending');
        setProblem('');
        try {
            setCode(await sendToNewPhone({ slot, key }));
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
                {phase === 'sent' ? (
                    <RNView style={styles.center}>
                        <Text style={styles.title}>{t('devices.sendCodeTitle')}</Text>
                        <Text style={styles.code} accessibilityLabel={code}>
                            {code}
                        </Text>
                        <Text style={styles.lede}>{t('devices.sendCodeBody')}</Text>
                        <Pressable style={[styles.primary, styles.stretch]} onPress={() => router.replace('/(tabs)')}>
                            <Text style={styles.primaryText}>{t('common.done')}</Text>
                        </Pressable>
                    </RNView>
                ) : (
                    <>
                        <RNView style={styles.icon}>
                            <Ionicons name="phone-portrait-outline" size={30} color={p.blue} />
                        </RNView>
                        <Text style={styles.lede}>{t('devices.sendLede')}</Text>
                        {problem ? <Text style={styles.problem}>{problem}</Text> : null}
                        <Pressable
                            style={[styles.primary, phase === 'sending' && styles.disabled]}
                            disabled={phase === 'sending' || !slot || !key}
                            onPress={() => void send()}
                        >
                            {phase === 'sending' ? (
                                <ActivityIndicator color="#FFFFFF" />
                            ) : (
                                <Text style={styles.primaryText}>{t('devices.sendConfirm')}</Text>
                            )}
                        </Pressable>
                        <Pressable style={styles.secondary} onPress={() => router.back()}>
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
        icon: {
            width: 56,
            height: 56,
            borderRadius: 28,
            backgroundColor: p.card,
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: 18,
        },
        title: { fontSize: 22, fontWeight: '700', color: p.textPrimary, marginBottom: 8, textAlign: 'center' },
        lede: { fontSize: 15, lineHeight: 22, color: p.textSecondary },
        code: {
            marginVertical: 24,
            fontSize: 40,
            fontWeight: '700',
            letterSpacing: 6,
            textAlign: 'center',
            color: p.textPrimary,
            fontVariant: ['tabular-nums'],
        },
        problem: { marginTop: 16, fontSize: 14, lineHeight: 20, color: p.danger },
        primary: {
            marginTop: 24,
            backgroundColor: p.blue,
            borderRadius: 14,
            paddingVertical: 16,
            paddingHorizontal: 20,
            alignItems: 'center',
        },
        primaryText: { color: '#FFFFFF', fontSize: 16, fontWeight: '600' },
        disabled: { opacity: 0.5 },
        secondary: { marginTop: 14, paddingVertical: 10, alignItems: 'center' },
        secondaryText: { color: p.blue, fontSize: 15, fontWeight: '600' },
        stretch: { alignSelf: 'stretch' },
    });
