// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A question an app asked the holder, drawn from the app's form and answered
 * here (services/app-form). Everything on this screen is a native component
 * the wallet chose: the app's words appear only as plain text under the app's
 * platform-verified name, attribute values under the wallet's own labels, and
 * every button carries the wallet's label for its kind. Answering signs with
 * the identity's passkey and goes to the app over attested RA-TLS.
 */

import { Ionicons } from '@expo/vector-icons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, Linking, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { isDeclining, type FormBlock } from '@/services/app-form';
import { answerForm, AnswerError, type AnswerFailure } from '@/services/app-form-answer';
import { attributeLabel } from '@/services/attributes';
import { useAppMessagesStore } from '@/stores/app-messages';

type Phase =
    | { kind: 'ready' }
    | { kind: 'busy'; action: string }
    | { kind: 'done'; actionKind: string }
    | { kind: 'failed'; reason: AnswerFailure };

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
    const [phase, setPhase] = useState<Phase>({ kind: 'ready' });

    // Opened from Access the form is already listed; from a push it may not
    // be yet, so look once.
    useEffect(() => {
        if (message || looked) return;
        void refresh().finally(() => setLooked(true));
    }, [message, looked, refresh]);

    const app = message?.appName || t('access.messageSomeApp');
    const form = message?.form;

    const answer = async (actionId: string, actionKind: string) => {
        if (!message || !form || !message.appId) return;
        setPhase({ kind: 'busy', action: actionId });
        try {
            await answerForm({ messageId: message.id, form, appId: message.appId, action: actionId });
            forget(message.id);
            setPhase({ kind: 'done', actionKind });
        } catch (e) {
            const reason = e instanceof AnswerError ? e.reason : 'unreachable';
            if (reason === 'gone') forget(message.id);
            // A cancelled biometric is not a failure worth a message: back to the form.
            setPhase(reason === 'cancelled' ? { kind: 'ready' } : { kind: 'failed', reason });
        }
    };

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
                    <Ionicons name="shield-checkmark-outline" size={16} color={p.textSecondary} />
                    <Text style={styles.fromText}>{t('appForm.from', { app })}</Text>
                </RNView>
                <RNView style={styles.card}>
                    <Text style={styles.title}>{form.title}</Text>
                    {form.blocks.map((b, i) => (
                        <Block key={i} block={b} styles={styles} t={t} />
                    ))}
                </RNView>

                {phase.kind === 'failed' ? (
                    <Text style={styles.error}>{t(`appForm.failed.${phase.reason}`, { app })}</Text>
                ) : null}

                <RNView style={styles.actions}>
                    {form.actions.map((a) => {
                        const declining = isDeclining(a.kind);
                        const busy = phase.kind === 'busy' && phase.action === a.id;
                        return (
                            <Pressable
                                key={a.id}
                                disabled={phase.kind === 'busy'}
                                onPress={() => void answer(a.id, a.kind)}
                                style={[styles.button, declining ? styles.buttonDecline : styles.buttonPrimary]}
                                accessibilityRole="button"
                            >
                                {busy ? (
                                    <ActivityIndicator color={declining ? p.danger : '#fff'} />
                                ) : (
                                    <Text style={declining ? styles.buttonDeclineText : styles.buttonPrimaryText}>
                                        {t(`appForm.action.${a.kind}`)}
                                    </Text>
                                )}
                            </Pressable>
                        );
                    })}
                </RNView>
                <Text style={styles.note}>{t('appForm.signNote', { app })}</Text>

                {message.link ? (
                    <Pressable onPress={() => void Linking.openURL(message.link!)} style={styles.link} hitSlop={8}>
                        <Text style={styles.linkText}>{t('appForm.openInApp', { app })}</Text>
                        <Ionicons name="open-outline" size={16} color={p.action} />
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
                    <Pressable style={styles.close} onPress={() => (router.canGoBack() ? router.back() : router.replace('/access'))}>
                        <Text style={styles.closeText}>{t('common.close')}</Text>
                    </Pressable>
                ) : null}
            </ScrollView>
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
        from: { flexDirection: 'row', alignItems: 'center', gap: 6 },
        fromText: { fontSize: 13, color: p.textSecondary },
        card: { backgroundColor: p.card, borderRadius: 14, padding: 18, gap: 12, borderWidth: 1, borderColor: p.border },
        title: { fontSize: 18, fontWeight: '700', color: p.textPrimary },
        text: { fontSize: 14.5, lineHeight: 21, color: p.textPrimary },
        divider: { height: StyleSheet.hairlineWidth, backgroundColor: p.border },
        fields: { gap: 8 },
        sectionLabel: { fontSize: 12, fontWeight: '600', color: p.textMuted, letterSpacing: 0.3 },
        fieldRow: { gap: 2 },
        fieldLabel: { fontSize: 12.5, color: p.textSecondary },
        fieldValue: { fontSize: 15, color: p.textPrimary },
        actions: { gap: 10 },
        button: { borderRadius: 14, paddingVertical: 14, alignItems: 'center' },
        buttonPrimary: { backgroundColor: p.action },
        buttonPrimaryText: { color: '#fff', fontSize: 16, fontWeight: '600' },
        buttonDecline: { borderWidth: 1, borderColor: p.danger },
        buttonDeclineText: { color: p.danger, fontSize: 16, fontWeight: '600' },
        note: { fontSize: 12.5, lineHeight: 18, color: p.textMuted, textAlign: 'center' },
        error: { fontSize: 13.5, lineHeight: 19, color: p.danger, textAlign: 'center' },
        link: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 6, paddingVertical: 6 },
        linkText: { color: p.action, fontSize: 14.5, fontWeight: '600' },
        close: { alignSelf: 'center', marginTop: 20, paddingVertical: 10, paddingHorizontal: 24 },
        closeText: { color: p.action, fontSize: 15, fontWeight: '600' },
    });
