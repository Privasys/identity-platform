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
 * shown and opens the attestation for the holder to review. Until then the
 * form's own words are not shown at all: they are unconfirmed text.
 *
 * A form that fails the check says why and shows nothing of itself. If the app
 * is not waiting on it, or the host is not the app's, it is removed at once;
 * if the app could not be reached or verified it stays, to try again.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, Linking, Modal, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { AttestationView } from '@/components/AttestationView';
import { SubPageHeader } from '@/components/SubPageHeader';
import { taskStyles } from '@/components/task-styles';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { isDeclining, type FormBlock } from '@/services/app-form';
import {
    answerForm,
    AnswerError,
    confirmFormSource,
    removedWhenRefused,
    type AnswerFailure,
    type ConfirmedSource,
} from '@/services/app-form-answer';
import { attributeLabel } from '@/services/attributes';
import { useAppMessagesStore } from '@/stores/app-messages';
import { notify } from '@/stores/notice';

type Phase =
    | { kind: 'checking' }
    | { kind: 'ready'; source: ConfirmedSource }
    | { kind: 'busy'; source: ConfirmedSource; action: string }
    // Carries what it shows: the message itself may already have been removed.
    | { kind: 'refused'; reason: AnswerFailure; app: string; invitation: boolean }
    // detail: the step and status that failed, so a report can name it.
    | { kind: 'failed'; source: ConfirmedSource; reason: AnswerFailure; detail?: string };

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
    const dismiss = useAppMessagesStore((s) => s.dismiss);
    const [looked, setLooked] = useState(false);
    const [phase, setPhase] = useState<Phase>({ kind: 'checking' });
    const [reviewing, setReviewing] = useState(false);

    // Opened from Access the form is already listed; from a push it may not
    // be yet, so look once.
    useEffect(() => {
        // Not once refused: a form just removed must not be listed back.
        if (message || looked || phase.kind === 'refused') return;
        void refresh().finally(() => setLooked(true));
    }, [message, looked, refresh, phase.kind]);

    const app = message?.appName || message?.appSlug || t('access.messageSomeApp');
    const form = message?.form;

    // Establish that the app sent it before anything can be answered.
    useEffect(() => {
        if (!message || !form || phase.kind !== 'checking') return;
        const invitation = message.kind === 'invitation';
        // Without an app id there is nothing to check it against.
        if (!message.appId) {
            setPhase({ kind: 'refused', reason: 'unverified', app, invitation });
            return;
        }
        let live = true;
        confirmFormSource({ form, appId: message.appId, appSlug: message.appSlug, platformHost: message.platformHost })
            .then((source) => live && setPhase({ kind: 'ready', source }))
            .catch((e) => {
                if (!live) return;
                const reason = e instanceof AnswerError ? e.reason : 'unreachable';
                setPhase({ kind: 'refused', reason, app, invitation });
                if (removedWhenRefused(reason)) void dismiss(message.id);
            });
        return () => {
            live = false;
        };
    }, [message, form, phase.kind, app, dismiss]);

    const leave = () => (router.canGoBack() ? router.back() : router.replace('/access'));

    const answer = async (source: ConfirmedSource, actionId: string, actionKind: string) => {
        if (!message || !form || !message.appId) return;
        setPhase({ kind: 'busy', source, action: actionId });
        try {
            await answerForm({ messageId: message.id, form, appId: message.appId, host: source.host, action: actionId });
            forget(message.id);
            // No page to say it worked: back to where the holder was, with
            // the message strip saying what was sent.
            notify(t('appForm.sent', { app }), t(`appForm.sentAs.${actionKind}`));
            leave();
        } catch (e) {
            const reason = e instanceof AnswerError ? e.reason : 'unreachable';
            if (reason === 'gone') forget(message.id);
            // A cancelled biometric is not a failure worth a message: back to the form.
            const detail = e instanceof Error ? e.message : String(e);
            if (reason !== 'cancelled') console.warn(`[ANSWER] failed (${reason}): ${detail}`);
            setPhase(reason === 'cancelled' ? { kind: 'ready', source } : { kind: 'failed', source, reason, detail });
        }
    };

    const source = phase.kind === 'ready' || phase.kind === 'busy' || phase.kind === 'failed' ? phase.source : undefined;

    const body = (() => {
        // Before the message: a refused form may already have been removed.
        if (phase.kind === 'refused') {
            const removed = removedWhenRefused(phase.reason);
            const closed = phase.reason === 'not-confirmed';
            return (
                <>
                    <Text style={styles.fromText}>{t('appForm.from', { app: phase.app })}</Text>
                    <RNView style={styles.refused} testID="app-form-refused">
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
                            testID="app-form-verified-host"
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

                {source ? (
                    <RNView style={styles.card}>
                        <Text style={styles.title}>{form.title}</Text>
                        {form.blocks.map((b, i) => (
                            <Block key={i} block={b} styles={styles} t={t} />
                        ))}
                    </RNView>
                ) : null}

                {phase.kind === 'failed' ? (
                    <>
                        <Text style={styles.error}>{t(`appForm.failed.${phase.reason}`, { app })}</Text>
                        {phase.detail && phase.detail !== phase.reason ? (
                            <Text style={styles.note} selectable testID="answer-failed-detail">
                                {phase.detail}
                            </Text>
                        ) : null}
                    </>
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
                                                <ActivityIndicator color={declining ? p.textPrimary : p.onGreen} />
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

                {source && message.link ? (
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
            <SubPageHeader
                title={
                    (phase.kind === 'refused' ? phase.invitation : message?.kind === 'invitation')
                        ? t('appForm.titleInvitation')
                        : t('appForm.titleRequest')
                }
            />
            <ScrollView contentContainerStyle={[styles.body, { paddingBottom: insets.bottom + 32 }]}>
                {body}
                {!message && looked && phase.kind !== 'refused' ? (
                    <Pressable
                        style={styles.doneButton}
                        onPress={leave}
                        accessibilityRole="button"
                    >
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

const makeStyles = (p: Palette) => ({
    ...taskStyles(p),
    ...StyleSheet.create({
        hostChecking: { fontSize: 13, color: p.textSecondary },
        hostVerified: { fontSize: 13, color: p.textSecondary, flexShrink: 1 },
        text: { fontSize: 14.5, lineHeight: 21, color: p.textPrimary },
        fields: { gap: 8 },
        sectionLabel: { fontSize: 12, fontWeight: '600', color: p.textMuted, letterSpacing: 0.3 },
        fieldRow: { gap: 2 },
        fieldLabel: { fontSize: 12.5, color: p.textSecondary },
        fieldValue: { fontSize: 15, color: p.textPrimary },
        link: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 6, paddingVertical: 6 },
        linkText: { color: p.blue, fontSize: 14.5, fontWeight: '600' },
    }),
});
