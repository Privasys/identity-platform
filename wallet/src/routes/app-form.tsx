// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A question an app asked the holder, drawn from the app's form and answered
 * here (services/app-form). Everything on this screen is a native component
 * the wallet chose: the app's words appear only as plain text under the app's
 * name, attribute values under the wallet's own labels, and every button
 * carries the wallet's label for its kind.
 *
 * Nothing can be answered until the wallet has established, without trusting
 * the platform, that the app itself sent the form: its own hostname, the app
 * id attested there, a verified attestation, and the app confirming the form
 * inside that channel (services/app-form-answer). The verified hostname is
 * shown and opens the attestation for the holder to review.
 */

import { Ionicons } from '@expo/vector-icons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, Linking, Modal, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { AttestationView } from '@/components/AttestationView';
import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { isDeclining, type FormBlock } from '@/services/app-form';
import {
    answerForm,
    AnswerError,
    confirmFormSource,
    type AnswerFailure,
    type ConfirmedSource,
} from '@/services/app-form-answer';
import { attributeLabel } from '@/services/attributes';
import { useAppMessagesStore } from '@/stores/app-messages';

type Phase =
    | { kind: 'checking' }
    | { kind: 'ready'; source: ConfirmedSource }
    | { kind: 'busy'; source: ConfirmedSource; action: string }
    | { kind: 'done'; actionKind: string }
    | { kind: 'refused'; reason: AnswerFailure }
    | { kind: 'failed'; source: ConfirmedSource; reason: AnswerFailure };

export default function AppFormScreen() {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const { id } = useLocalSearchParams<{ id?: string }>();
    const message = useAppMessagesStore((s) => s.messages.find((m) => m.id === id));
    const refresh = useAppMessagesStore((s) => s.refresh);
    const forget = useAppMessagesStore((s) => s.forget);
    const [looked, setLooked] = useState(false);
    const [phase, setPhase] = useState<Phase>({ kind: 'checking' });
    const [reviewing, setReviewing] = useState(false);

    // Opened from Access the form is already listed; from a push it may not
    // be yet, so look once.
    useEffect(() => {
        if (message || looked) return;
        void refresh().finally(() => setLooked(true));
    }, [message, looked, refresh]);

    const app = message?.appName || message?.appSlug || t('access.messageSomeApp');
    const form = message?.form;

    // Establish that the app sent it before anything can be answered.
    useEffect(() => {
        if (!message || !form || !message.appId || phase.kind !== 'checking') return;
        let live = true;
        confirmFormSource({ form, appId: message.appId, appSlug: message.appSlug, platformHost: message.platformHost })
            .then((source) => live && setPhase({ kind: 'ready', source }))
            .catch((e) => live && setPhase({ kind: 'refused', reason: e instanceof AnswerError ? e.reason : 'unreachable' }));
        return () => {
            live = false;
        };
    }, [message, form, phase.kind]);

    const leave = () => (router.canGoBack() ? router.back() : router.replace('/access'));

    // Once answered, return on its own, as the other success screens do; the
    // Done button stays for a holder who does not wait.
    useEffect(() => {
        if (phase.kind !== 'done') return;
        const timer = setTimeout(leave, 1500);
        return () => clearTimeout(timer);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [phase.kind]);

    const answer = async (source: ConfirmedSource, actionId: string, actionKind: string) => {
        if (!message || !form || !message.appId) return;
        setPhase({ kind: 'busy', source, action: actionId });
        try {
            await answerForm({ messageId: message.id, form, appId: message.appId, host: source.host, action: actionId });
            forget(message.id);
            setPhase({ kind: 'done', actionKind });
        } catch (e) {
            const reason = e instanceof AnswerError ? e.reason : 'unreachable';
            if (reason === 'gone') forget(message.id);
            // A cancelled biometric is not a failure worth a message: back to the form.
            setPhase(reason === 'cancelled' ? { kind: 'ready', source } : { kind: 'failed', source, reason });
        }
    };

    const source = phase.kind === 'ready' || phase.kind === 'busy' || phase.kind === 'failed' ? phase.source : undefined;

    const body = (() => {
        if (phase.kind === 'done') {
            return (
                <RNView style={styles.centre}>
                    <Ionicons name="checkmark-circle" size={48} color={p.green} />
                    <Text style={styles.doneTitle}>{t('appForm.sent', { app })}</Text>
                    <Text style={styles.note}>{t(`appForm.sentAs.${phase.actionKind}`)}</Text>
                </RNView>
            );
        }
        if (!message) {
            return looked ? (
                <Text style={styles.note}>{t('appForm.gone')}</Text>
            ) : (
                <ActivityIndicator style={styles.spinner} color={p.textSecondary} />
            );
        }
        if (!form) {
            return <Text style={styles.note}>{t('appForm.unreadable', { app })}</Text>;
        }
        return (
            <>
                <RNView style={styles.from}>
                    <Text style={styles.fromText}>{t('appForm.from', { app })}</Text>
                    {phase.kind === 'checking' ? (
                        <RNView style={styles.hostRow}>
                            <ActivityIndicator size="small" color={p.textSecondary} />
                            <Text style={styles.hostChecking}>{t('appForm.checking')}</Text>
                        </RNView>
                    ) : source ? (
                        <Pressable
                            style={styles.hostRow}
                            onPress={() => setReviewing(true)}
                            accessibilityRole="button"
                            accessibilityLabel={t('appForm.reviewAttestation', { host: source.host })}
                        >
                            <Ionicons name="shield-checkmark" size={16} color={p.green} />
                            <Text style={styles.hostVerified}>{source.host}</Text>
                            <Ionicons name="chevron-forward" size={14} color={p.textSecondary} />
                        </Pressable>
                    ) : null}
                </RNView>

                <RNView style={[styles.card, phase.kind === 'refused' && styles.cardDimmed]}>
                    <Text style={styles.title}>{form.title}</Text>
                    {form.blocks.map((b, i) => (
                        <Block key={i} block={b} styles={styles} t={t} />
                    ))}
                </RNView>

                {phase.kind === 'refused' ? (
                    <Text style={styles.error}>{t(`appForm.refused.${phase.reason}`, { app })}</Text>
                ) : null}
                {phase.kind === 'failed' ? (
                    <Text style={styles.error}>{t(`appForm.failed.${phase.reason}`, { app })}</Text>
                ) : null}

                {source ? (
                    <>
                        <RNView style={styles.actions}>
                            {/* As on the approval screen: the declining choice
                                first and neutral, the affirming one wider and in
                                the brand green. */}
                            {[...form.actions]
                                .sort((a, b) => Number(!isDeclining(a.kind)) - Number(!isDeclining(b.kind)))
                                .map((a) => {
                                    const declining = isDeclining(a.kind);
                                    const busy = phase.kind === 'busy' && phase.action === a.id;
                                    return (
                                        <Pressable
                                            key={a.id}
                                            disabled={phase.kind === 'busy'}
                                            onPress={() => void answer(source, a.id, a.kind)}
                                            style={[
                                                declining ? styles.declineButton : styles.affirmButton,
                                                phase.kind === 'busy' && !busy && styles.buttonIdle,
                                            ]}
                                            accessibilityRole="button"
                                        >
                                            {busy ? (
                                                <ActivityIndicator color={declining ? p.textPrimary : '#FFFFFF'} />
                                            ) : (
                                                <Text style={declining ? styles.declineButtonText : styles.affirmButtonText}>
                                                    {t(`appForm.action.${a.kind}`)}
                                                </Text>
                                            )}
                                        </Pressable>
                                    );
                                })}
                        </RNView>
                        <Text style={styles.note}>{t('appForm.signNote', { app })}</Text>
                    </>
                ) : null}

                {message.link ? (
                    <Pressable onPress={() => void Linking.openURL(message.link!)} style={styles.link} hitSlop={8}>
                        <Text style={styles.linkText}>{t('appForm.openInApp', { app })}</Text>
                        <Ionicons name="open-outline" size={16} color={p.blue} />
                    </Pressable>
                ) : null}
            </>
        );
    })();

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={message?.kind === 'invitation' ? t('appForm.titleInvitation') : t('appForm.titleRequest')} />
            <ScrollView contentContainerStyle={[styles.body, { paddingBottom: insets.bottom + 32 }]}>
                {body}
                {phase.kind === 'done' || (!message && looked) ? (
                    <Pressable
                        style={styles.doneButton}
                        onPress={leave}
                        accessibilityRole="button"
                    >
                        <Text style={styles.affirmButtonText}>{t('common.done')}</Text>
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

function Block({
    block,
    styles,
    t,
}: {
    block: FormBlock;
    styles: ReturnType<typeof makeStyles>;
    t: (k: string) => string;
}) {
    switch (block.type) {
        case 'text':
            // Plain text, never parsed: no links, no markup.
            return <Text style={styles.text}>{block.text}</Text>;
        case 'divider':
            return <RNView style={styles.divider} />;
        case 'fields':
            return (
                <RNView style={styles.fields}>
                    {block.items.map((it, i) => (
                        <RNView key={i} style={styles.fieldRow}>
                            <Text style={styles.fieldLabel}>{it.label}</Text>
                            <Text style={styles.fieldValue}>{it.value}</Text>
                        </RNView>
                    ))}
                </RNView>
            );
        case 'attributes':
            if (block.values.length === 0) return null;
            return (
                <RNView style={styles.fields}>
                    <Text style={styles.sectionLabel}>{t('appForm.presented')}</Text>
                    {block.values.map(([key, value]) => (
                        <RNView key={key} style={styles.fieldRow}>
                            <Text style={styles.fieldLabel}>{attributeLabel(key)}</Text>
                            <Text style={styles.fieldValue}>{value}</Text>
                        </RNView>
                    ))}
                </RNView>
            );
    }
}

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        screen: { flex: 1, backgroundColor: p.screenBg },
        body: { padding: 20, gap: 14 },
        spinner: { marginTop: 40 },
        centre: { alignItems: 'center', gap: 10, marginTop: 40 },
        doneTitle: { fontSize: 18, fontWeight: '700', color: p.textPrimary, textAlign: 'center' },
        from: { gap: 4 },
        fromText: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
        hostRow: { flexDirection: 'row', alignItems: 'center', gap: 6, paddingVertical: 2 },
        hostChecking: { fontSize: 13, color: p.textSecondary },
        hostVerified: { fontSize: 13, color: p.textSecondary, flexShrink: 1 },
        card: { backgroundColor: p.card, borderRadius: 14, padding: 18, gap: 12, borderWidth: 1, borderColor: p.border },
        cardDimmed: { opacity: 0.55 },
        title: { fontSize: 18, fontWeight: '700', color: p.textPrimary },
        text: { fontSize: 14.5, lineHeight: 21, color: p.textPrimary },
        divider: { height: StyleSheet.hairlineWidth, backgroundColor: p.border },
        fields: { gap: 8 },
        sectionLabel: { fontSize: 12, fontWeight: '600', color: p.textMuted, letterSpacing: 0.3 },
        fieldRow: { gap: 2 },
        fieldLabel: { fontSize: 12.5, color: p.textSecondary },
        fieldValue: { fontSize: 15, color: p.textPrimary },
        // The approval screen's buttons (components/AttestationView).
        actions: { flexDirection: 'row', gap: 10 },
        declineButton: { flex: 1, paddingVertical: 15, borderRadius: 12, alignItems: 'center', backgroundColor: p.buttonNeutral },
        declineButtonText: { fontSize: 16, fontWeight: '600', color: p.textPrimary },
        affirmButton: { flex: 1.35, paddingVertical: 15, borderRadius: 12, alignItems: 'center', backgroundColor: p.green },
        affirmButtonText: { fontSize: 16, fontWeight: '600', color: '#FFFFFF' },
        buttonIdle: { opacity: 0.5 },
        // The Done of the other finished screens (device-add, verify-email).
        doneButton: { marginTop: 24, paddingVertical: 16, paddingHorizontal: 20, borderRadius: 14, alignItems: 'center', backgroundColor: p.blue },
        note: { fontSize: 12.5, lineHeight: 18, color: p.textMuted, textAlign: 'center' },
        error: { fontSize: 13.5, lineHeight: 19, color: p.danger, textAlign: 'center' },
        link: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 6, paddingVertical: 6 },
        linkText: { color: p.blue, fontSize: 14.5, fontWeight: '600' },
    });
