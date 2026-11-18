// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * An app asking the holder to approve one act (services/approval). The
 * wallet owns the whole screen: the app's verified name and host, its title
 * and labelled lines as plain text, the assurance asked for, the time left,
 * and two answers the wallet labels itself.
 *
 * Nothing can be answered until the wallet has established, without trusting
 * the platform, that the app itself sent it (services/approval-answer, the
 * same check as forms). Answering asks for a fresh biometric, then the
 * passkey; the token goes to the app over RA-TLS. Until the check passes the
 * approval's own words are not shown at all: they are unconfirmed text.
 *
 * An approval that fails the check says why and shows nothing of itself. If
 * the app is not waiting on it, or the host is not the app's, it is removed at
 * once; if the app could not be reached or verified it stays, to try again.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, Modal, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { AttestationView } from '@/components/AttestationView';
import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { AnswerError, removedWhenRefused, type AnswerFailure, type ConfirmedSource } from '@/services/app-form-answer';
import type { Decision } from '@/services/approval';
import { answerApproval, confirmApprovalSource } from '@/services/approval-answer';
import { useAppMessagesStore } from '@/stores/app-messages';
import { notify } from '@/stores/notice';

type Phase =
    | { kind: 'checking' }
    | { kind: 'ready'; source: ConfirmedSource }
    | { kind: 'busy'; source: ConfirmedSource; decision: Decision }
    // Carries the app's name: the message itself may already have been removed.
    | { kind: 'refused'; reason: AnswerFailure; app: string }
    | { kind: 'failed'; source: ConfirmedSource; reason: AnswerFailure };

function useSecondsLeft(expiresAt?: number): number | undefined {
    const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
    useEffect(() => {
        if (!expiresAt) return;
        const timer = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
        return () => clearInterval(timer);
    }, [expiresAt]);
    return expiresAt ? Math.max(0, expiresAt - now) : undefined;
}

export default function ApprovalScreen() {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const { id } = useLocalSearchParams<{ id?: string }>();
    const message = useAppMessagesStore((s) => s.messages.find((m) => m.id === id));
    const refresh = useAppMessagesStore((s) => s.refresh);
    const forget = useAppMessagesStore((s) => s.forget);
    const dismiss = useAppMessagesStore((s) => s.dismiss);
    const [looked, setLooked] = useState(false);
    const [phase, setPhase] = useState<Phase>({ kind: 'checking' });
    const [reviewing, setReviewing] = useState(false);

    useEffect(() => {
        // Not once refused: an approval just removed must not be listed back.
        if (message || looked || phase.kind === 'refused') return;
        void refresh().finally(() => setLooked(true));
    }, [message, looked, refresh, phase.kind]);

    const app = message?.appName || message?.appSlug || t('access.messageSomeApp');
    const approval = message?.approval;
    const left = useSecondsLeft(message?.expiresAt);
    const expired = left === 0;

    useEffect(() => {
        if (!message || !approval || phase.kind !== 'checking') return;
        // Without an app id there is nothing to check it against.
        if (!message.appId) {
            setPhase({ kind: 'refused', reason: 'unverified', app });
            return;
        }
        let live = true;
        confirmApprovalSource({ approval, appId: message.appId, appSlug: message.appSlug, platformHost: message.platformHost })
            .then((source) => live && setPhase({ kind: 'ready', source }))
            .catch((e) => {
                if (!live) return;
                const reason = e instanceof AnswerError ? e.reason : 'unreachable';
                setPhase({ kind: 'refused', reason, app });
                if (removedWhenRefused(reason)) void dismiss(message.id);
            });
        return () => {
            live = false;
        };
    }, [message, approval, phase.kind, app, dismiss]);

    const leave = () => (router.canGoBack() ? router.back() : router.replace('/access'));

    const answer = async (source: ConfirmedSource, decision: Decision) => {
        if (!message || !approval || !message.appId) return;
        setPhase({ kind: 'busy', source, decision });
        try {
            await answerApproval({
                messageId: message.id,
                approval,
                appId: message.appId,
                host: source.host,
                decision,
                prompt: t(`approval.prompt.${decision}`, { app }),
                cancel: t('common.cancel'),
            });
            forget(message.id);
            notify(t(`approval.done.${decision}`, { app }), approval.title);
            leave();
        } catch (e) {
            const reason = e instanceof AnswerError ? e.reason : 'unreachable';
            if (reason === 'gone') forget(message.id);
            setPhase(reason === 'cancelled' ? { kind: 'ready', source } : { kind: 'failed', source, reason });
        }
    };

    const source = phase.kind === 'ready' || phase.kind === 'busy' || phase.kind === 'failed' ? phase.source : undefined;
    const supported = approval?.assurance === 'device';

    const body = (() => {
        // Before the message: a refused approval may already have been removed.
        if (phase.kind === 'refused') {
            const removed = removedWhenRefused(phase.reason);
            const closed = phase.reason === 'not-confirmed';
            return (
                <>
                    <Text style={styles.fromText}>{t('appForm.from', { app: phase.app })}</Text>
                    <RNView style={styles.refused} testID="approval-refused">
                        <Ionicons
                            name={closed ? 'checkmark-circle-outline' : 'warning-outline'}
                            size={32}
                            color={closed ? p.textSecondary : p.danger}
                        />
                        <Text style={closed ? styles.closed : styles.error}>
                            {closed ? t('appForm.closed') : t(`appForm.refused.${phase.reason}`, { app: phase.app })}
                        </Text>
                    </RNView>
                    {removed ? (
                        <Pressable style={styles.doneButton} onPress={leave} accessibilityRole="button">
                            <Text style={styles.doneButtonText}>{t('common.done')}</Text>
                        </Pressable>
                    ) : (
                        <RNView style={styles.actions}>
                            <Pressable
                                style={styles.declineButton}
                                onPress={() => {
                                    if (message) void dismiss(message.id);
                                    leave();
                                }}
                                accessibilityRole="button"
                            >
                                <Text style={styles.declineButtonText}>{t('common.remove')}</Text>
                            </Pressable>
                            <Pressable
                                style={styles.retryButton}
                                onPress={() => setPhase({ kind: 'checking' })}
                                accessibilityRole="button"
                            >
                                <Text style={styles.doneButtonText}>{t('common.retry')}</Text>
                            </Pressable>
                        </RNView>
                    )}
                </>
            );
        }
        if (!message) {
            return looked ? (
                <Text style={styles.note}>{t('appForm.gone')}</Text>
            ) : (
                <ActivityIndicator style={styles.spinner} color={p.textSecondary} />
            );
        }
        if (!approval) {
            return <Text style={styles.note}>{t('appForm.unreadable', { app })}</Text>;
        }
        return (
            <>
                <RNView style={styles.from}>
                    <Text style={styles.fromText}>{t('appForm.from', { app })}</Text>
                    {phase.kind === 'checking' ? (
                        <RNView style={styles.hostRow}>
                            <ActivityIndicator size="small" color={p.textSecondary} />
                            <Text style={styles.hostMuted}>{t('appForm.checking')}</Text>
                        </RNView>
                    ) : source ? (
                        <Pressable
                            style={styles.hostRow}
                            testID="approval-verified-host"
                            onPress={() => setReviewing(true)}
                            accessibilityRole="button"
                            accessibilityLabel={t('appForm.reviewAttestation', { host: source.host })}
                        >
                            <Ionicons name="shield-checkmark" size={16} color={p.green} />
                            <Text style={styles.hostMuted}>{source.host}</Text>
                            <Ionicons name="chevron-forward" size={14} color={p.textSecondary} />
                        </Pressable>
                    ) : null}
                </RNView>

                {source ? (
                    <RNView style={[styles.card, expired && styles.cardDimmed]}>
                        <Text style={styles.title}>{approval.title}</Text>
                        {approval.lines.length > 0 ? (
                            <RNView style={styles.lines}>
                                {approval.lines.map((l, i) => (
                                    <RNView key={i} style={styles.line}>
                                        <Text style={styles.lineLabel}>{l.label}</Text>
                                        <Text style={styles.lineValue}>{l.value}</Text>
                                    </RNView>
                                ))}
                            </RNView>
                        ) : null}
                        <RNView style={styles.divider} />
                        <RNView style={styles.metaRow}>
                            <Ionicons
                                name={approval.assurance === 'gov-presence' ? 'scan-outline' : 'finger-print-outline'}
                                size={16}
                                color={p.textSecondary}
                            />
                            <Text style={styles.meta}>{t(`approval.assurance.${approval.assurance}`)}</Text>
                        </RNView>
                        {left !== undefined ? (
                            <RNView style={styles.metaRow}>
                                <Ionicons name="time-outline" size={16} color={expired ? p.danger : p.textSecondary} />
                                <Text style={[styles.meta, expired && { color: p.danger }]}>
                                    {expired
                                        ? t('approval.expired', { app })
                                        : t('approval.timeLeft', {
                                              time: `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`,
                                          })}
                                </Text>
                            </RNView>
                        ) : null}
                    </RNView>
                ) : null}

                {phase.kind === 'failed' ? (
                    <Text style={styles.error}>{t(`appForm.failed.${phase.reason}`, { app })}</Text>
                ) : null}
                {source && !supported ? <Text style={styles.error}>{t('approval.unsupported')}</Text> : null}

                {source && supported && !expired ? (
                    <>
                        <RNView style={styles.actions}>
                            {(['decline', 'approve'] as Decision[]).map((d) => {
                                const declining = d === 'decline';
                                const busy = phase.kind === 'busy' && phase.decision === d;
                                return (
                                    <Pressable
                                        key={d}
                                        disabled={phase.kind === 'busy'}
                                        onPress={() => void answer(source, d)}
                                        style={[
                                            declining ? styles.declineButton : styles.affirmButton,
                                            phase.kind === 'busy' && !busy && styles.buttonIdle,
                                        ]}
                                        accessibilityRole="button"
                                    >
                                        {busy ? (
                                            <ActivityIndicator color={declining ? p.textPrimary : p.onGreen} />
                                        ) : (
                                            <Text style={declining ? styles.declineButtonText : styles.affirmButtonText}>
                                                {t(`appForm.action.${d}`)}
                                            </Text>
                                        )}
                                    </Pressable>
                                );
                            })}
                        </RNView>
                        <Text style={styles.note}>{t('appForm.signNote', { app })}</Text>
                    </>
                ) : null}
            </>
        );
    })();

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('approval.title')} />
            <ScrollView contentContainerStyle={[styles.body, { paddingBottom: insets.bottom + 32 }]}>
                {body}
                {phase.kind !== 'refused' && ((!message && looked) || expired) ? (
                    <Pressable style={styles.doneButton} onPress={leave} accessibilityRole="button">
                        <Text style={styles.doneButtonText}>{t('common.done')}</Text>
                    </Pressable>
                ) : null}
            </ScrollView>

            {source ? (
                <Modal visible={reviewing} animationType="slide" onRequestClose={() => setReviewing(false)}>
                    <AttestationView
                        attestation={source.attestation}
                        rpId={source.host}
                        displayName={message?.appName}
                        isChanged={false}
                        verificationLevel="fresh-as-verified"
                        verification={{ status: 'verified', mode: source.mode, challenged: source.challenged }}
                        reviewOnly
                        onApprove={() => setReviewing(false)}
                        onReject={() => setReviewing(false)}
                    />
                </Modal>
            ) : null}
        </RNView>
    );
}

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        screen: { flex: 1, backgroundColor: p.screenBg },
        body: { padding: 20, gap: 14 },
        spinner: { marginTop: 40 },
        from: { gap: 4 },
        fromText: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
        hostRow: { flexDirection: 'row', alignItems: 'center', gap: 6, paddingVertical: 2 },
        hostMuted: { fontSize: 13, color: p.textSecondary, flexShrink: 1 },
        card: { backgroundColor: p.card, borderRadius: 14, padding: 18, gap: 12, borderWidth: 1, borderColor: p.border },
        cardDimmed: { opacity: 0.55 },
        refused: { alignItems: 'center', gap: 12, paddingVertical: 24, paddingHorizontal: 8 },
        closed: { fontSize: 15, lineHeight: 21, color: p.textSecondary, textAlign: 'center' },
        retryButton: { flex: 1.35, paddingVertical: 15, borderRadius: 12, alignItems: 'center', backgroundColor: p.action },
        title: { fontSize: 18, fontWeight: '700', color: p.textPrimary },
        lines: { gap: 8 },
        line: { gap: 2 },
        lineLabel: { fontSize: 12.5, color: p.textSecondary },
        lineValue: { fontSize: 15, color: p.textPrimary },
        divider: { height: StyleSheet.hairlineWidth, backgroundColor: p.border },
        metaRow: { flexDirection: 'row', alignItems: 'center', gap: 8 },
        meta: { fontSize: 13, color: p.textSecondary, flexShrink: 1 },
        // The approval screen's buttons (components/AttestationView).
        actions: { flexDirection: 'row', gap: 10 },
        declineButton: { flex: 1, paddingVertical: 15, borderRadius: 12, alignItems: 'center', backgroundColor: p.buttonNeutral },
        declineButtonText: { fontSize: 16, fontWeight: '600', color: p.textPrimary },
        affirmButton: { flex: 1.35, paddingVertical: 15, borderRadius: 12, alignItems: 'center', backgroundColor: p.green },
        affirmButtonText: { fontSize: 16, fontWeight: '600', color: p.onGreen },
        buttonIdle: { opacity: 0.5 },
        doneButton: { marginTop: 24, paddingVertical: 16, paddingHorizontal: 20, borderRadius: 14, alignItems: 'center', backgroundColor: p.action },
        doneButtonText: { fontSize: 16, fontWeight: '600', color: '#FFFFFF' },
        note: { fontSize: 12.5, lineHeight: 18, color: p.textMuted, textAlign: 'center' },
        error: { fontSize: 13.5, lineHeight: 19, color: p.danger, textAlign: 'center' },
    });
