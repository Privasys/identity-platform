// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * https://privasys.id/account/delete/confirm?r=<request id>: the holder asked
 * privasys.id to delete their account, and the page hands over to the wallet
 * (a link on the same phone, a QR code on a computer). Continue signs in afresh
 * (the biometric prompt is the confirmation), registers the deletion, then
 * marks every identity this wallet holds (services/account-deletion).
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useMemo, useState } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { taskStyles } from '@/components/task-styles';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { confirmDeletion, deletionDate, DeletionError } from '@/services/account-deletion';

/** What privasys.id waits before deleting: shown before the holder confirms. */
const WAIT_DAYS = 7;

type Phase = 'asking' | 'working' | 'scheduled' | 'failed';

export default function ConfirmAccountDeletion() {
    const { t } = useTranslation();
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => ({ ...taskStyles(p), ...makeStyles(p) }), [p]);
    const params = useLocalSearchParams<{ r?: string }>();
    const requestId = String(params.r ?? '');

    const [phase, setPhase] = useState<Phase>(requestId ? 'asking' : 'failed');
    const [deleteAt, setDeleteAt] = useState<string | null>(null);
    const [problem, setProblem] = useState(requestId ? '' : t('accountDeletion.expired'));

    const leave = () => {
        if (router.canGoBack()) router.back();
        else router.replace('/(tabs)');
    };

    const confirm = async () => {
        if (phase === 'working') return;
        setPhase('working');
        try {
            setDeleteAt(await confirmDeletion(requestId));
            setPhase('scheduled');
        } catch (e: any) {
            if (e instanceof DeletionError && e.status === 404) setProblem(t('accountDeletion.expired'));
            else if (e instanceof DeletionError && e.status === 409) setProblem(t('accountDeletion.blocked'));
            else setProblem(t('accountDeletion.failed', { reason: e?.message ?? String(e) }));
            setPhase('failed');
        }
    };

    const estimated = deletionDate(new Date(Date.now() + WAIT_DAYS * 24 * 3600 * 1000));

    return (
        <RNView style={styles.screen} testID="account-delete-confirm">
            <SubPageHeader title={t('accountDeletion.title')} />
            <ScrollView contentContainerStyle={[styles.body, { paddingBottom: insets.bottom + 32 }]}>
                {(phase === 'asking' || phase === 'working') && (
                    <>
                        <RNView style={styles.card}>
                            <Text style={styles.title}>{t('accountDeletion.confirmTitle')}</Text>
                            <Text style={styles.lineValue}>{t('accountDeletion.confirmBody', { date: estimated })}</Text>
                            <RNView style={styles.divider} />
                            <RNView style={styles.metaRow}>
                                <Ionicons name="trash-outline" size={16} color={p.textSecondary} />
                                <Text style={styles.meta}>{t('accountDeletion.confirmWhatGoes')}</Text>
                            </RNView>
                            <RNView style={styles.metaRow}>
                                <Ionicons name="time-outline" size={16} color={p.textSecondary} />
                                <Text style={styles.meta}>{t('accountDeletion.confirmCancel')}</Text>
                            </RNView>
                        </RNView>
                        <RNView style={styles.actions}>
                            <Pressable style={styles.declineButton} onPress={leave} disabled={phase === 'working'}>
                                <Text style={styles.declineButtonText}>{t('common.notNow')}</Text>
                            </Pressable>
                            <Pressable
                                style={[styles.continueButton, phase === 'working' && styles.buttonIdle]}
                                onPress={() => void confirm()}
                                disabled={phase === 'working'}
                                testID="account-delete-continue"
                            >
                                {phase === 'working' ? (
                                    <ActivityIndicator color="#FFFFFF" />
                                ) : (
                                    <Text style={styles.continueText}>{t('common.continue')}</Text>
                                )}
                            </Pressable>
                        </RNView>
                    </>
                )}

                {phase === 'scheduled' && (
                    <RNView style={styles.refused}>
                        <Ionicons name="calendar-outline" size={40} color={p.textSecondary} />
                        <Text style={styles.title}>{t('accountDeletion.scheduledTitle')}</Text>
                        <Text style={styles.closed}>
                            {t('accountDeletion.scheduledBody', {
                                date: deleteAt ? deletionDate(new Date(deleteAt)) : estimated,
                            })}
                        </Text>
                        <Pressable style={[styles.doneButton, styles.stretch]} onPress={() => router.replace('/export')}>
                            <Text style={styles.doneButtonText}>{t('accountDeletion.saveCopy')}</Text>
                        </Pressable>
                        <Pressable onPress={() => router.replace('/(tabs)')} hitSlop={8}>
                            <Text style={styles.link}>{t('common.done')}</Text>
                        </Pressable>
                    </RNView>
                )}

                {phase === 'failed' && (
                    <RNView style={styles.refused}>
                        <Ionicons name="alert-circle-outline" size={40} color={p.textSecondary} />
                        <Text style={styles.closed}>{problem}</Text>
                        <Pressable style={[styles.doneButton, styles.stretch]} onPress={leave}>
                            <Text style={styles.doneButtonText}>{t('common.done')}</Text>
                        </Pressable>
                    </RNView>
                )}
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        // The wallet's Continue: the action blue; the biometric prompt that
        // follows is implicit.
        continueButton: { flex: 1.35, paddingVertical: 15, borderRadius: 12, alignItems: 'center', backgroundColor: p.action },
        continueText: { fontSize: 16, fontWeight: '600', color: '#FFFFFF' },
        stretch: { alignSelf: 'stretch' },
        link: { fontSize: 15, fontWeight: '600', color: p.action, paddingVertical: 6 },
    });
