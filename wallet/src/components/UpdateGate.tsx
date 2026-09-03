// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * "Update this wallet" — shown over everything when the running build is below
 * the published floor.
 *
 * Two shapes, one screen. A `recommended` notice can be dismissed and says so;
 * a `required` one cannot, and the only way past it is the store. The severity
 * comes from the server rather than from the app, so a release can be pushed
 * hard or soft without a new build deciding in advance which it is.
 *
 * The screen leads with what stops working, not with the version number. A
 * person asked to go to the App Store deserves to know what they lose by not
 * going, and "1.3.90 is below 1.3.92" tells them nothing. The version pair is
 * on the screen, at the bottom, because it is what a support conversation
 * needs.
 *
 * The prose is server-supplied and therefore untranslated beyond whatever
 * languages the manifest carries; the chrome around it is the app's own and is
 * translated properly. That split is deliberate: the reason a specific release
 * is retired cannot come from a catalogue written before that release existed.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useMemo } from 'react';
import { Linking, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { storeUrl, type UpdateNotice } from '@/services/app-version';

export function UpdateGate({
    notice,
    onDismiss,
}: {
    notice: UpdateNotice;
    /** Absent for a required notice, which is what makes it required. */
    onDismiss?: () => void;
}) {
    const { t } = useTranslation();
    const p = usePalette();
    const insets = useSafeAreaInsets();
    const styles = useMemo(() => makeStyles(p), [p]);
    const required = notice.level === 'required';

    return (
        <RNView style={[styles.screen, { paddingTop: insets.top }]}>
            <RNView style={styles.header}>
                <Ionicons
                    name={required ? 'alert-circle' : 'arrow-up-circle-outline'}
                    size={40}
                    color="#FFFFFF"
                />
                <Text style={styles.headerTitle}>
                    {required ? t('update.requiredTitle') : t('update.recommendedTitle')}
                </Text>
            </RNView>

            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={[styles.content, { paddingBottom: insets.bottom + 24 }]}
                showsVerticalScrollIndicator={false}
            >
                <Text style={styles.title}>{notice.text.title}</Text>
                <Text style={styles.body}>{notice.text.body}</Text>

                {notice.text.changes.length > 0 && (
                    <RNView style={styles.card}>
                        <Text style={styles.cardLabel}>{t('update.whatChanges')}</Text>
                        {notice.text.changes.map((line, i) => (
                            <RNView key={i} style={styles.changeRow}>
                                <Ionicons
                                    name="ellipse"
                                    size={6}
                                    color={p.textMuted}
                                    style={styles.bullet}
                                />
                                <Text style={styles.changeText}>{line}</Text>
                            </RNView>
                        ))}
                    </RNView>
                )}

                {notice.learnMoreUrl ? (
                    <Pressable
                        onPress={() => void Linking.openURL(notice.learnMoreUrl!)}
                        hitSlop={8}
                        accessibilityRole="link"
                    >
                        <Text style={styles.learnMore}>{t('update.learnMore')}</Text>
                    </Pressable>
                ) : null}

                {/* Small, factual, and last: this is what a support conversation
                    asks for, not what the reader is here to decide. */}
                <Text style={styles.versions}>
                    {t('update.versions', { current: notice.current, minimum: notice.minimum })}
                </Text>
            </ScrollView>

            <RNView style={[styles.actions, { paddingBottom: insets.bottom + 16 }]}>
                <Pressable
                    style={styles.primaryButton}
                    onPress={() => void Linking.openURL(storeUrl())}
                    accessibilityRole="button"
                >
                    <Text style={styles.primaryButtonText}>{t('update.openStore')}</Text>
                </Pressable>
                {onDismiss ? (
                    <Pressable onPress={onDismiss} hitSlop={8} accessibilityRole="button">
                        <Text style={styles.dismissText}>{t('update.notNow')}</Text>
                    </Pressable>
                ) : null}
            </RNView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { ...StyleSheet.absoluteFillObject, backgroundColor: p.screenBg, zIndex: 100 },
    header: {
        backgroundColor: p.green,
        paddingHorizontal: 24,
        paddingTop: 16,
        paddingBottom: 24,
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28,
        alignItems: 'center',
        gap: 10,
    },
    headerTitle: {
        fontSize: 24,
        fontWeight: '700',
        color: '#FFFFFF',
        letterSpacing: -0.4,
        textAlign: 'center',
    },
    scrollView: { flex: 1 },
    content: { padding: 24, gap: 16 },
    title: {
        fontSize: 20,
        fontWeight: '700',
        color: p.textPrimary,
        letterSpacing: -0.3,
    },
    body: { fontSize: 15, lineHeight: 22, color: p.textSecondary },
    card: { backgroundColor: p.card, borderRadius: 12, padding: 16, gap: 10 },
    cardLabel: {
        fontSize: 12,
        fontWeight: '700',
        color: p.textMuted,
        letterSpacing: 0.6,
        textTransform: 'uppercase',
    },
    changeRow: { flexDirection: 'row', alignItems: 'flex-start', gap: 10 },
    bullet: { marginTop: 7 },
    changeText: { flex: 1, fontSize: 14, lineHeight: 20, color: p.textSecondary },
    learnMore: { fontSize: 14, fontWeight: '600', color: p.blue },
    versions: { fontSize: 12, color: p.textMuted, marginTop: 4 },
    actions: {
        paddingHorizontal: 24,
        paddingTop: 12,
        gap: 14,
        alignItems: 'center',
        borderTopWidth: StyleSheet.hairlineWidth,
        borderTopColor: p.border,
    },
    primaryButton: {
        backgroundColor: p.green,
        borderRadius: 12,
        paddingVertical: 16,
        alignSelf: 'stretch',
        alignItems: 'center',
    },
    primaryButtonText: { fontSize: 16, fontWeight: '700', color: '#FFFFFF' },
    dismissText: { fontSize: 15, fontWeight: '600', color: p.textSecondary },
});
