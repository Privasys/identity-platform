// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * "How connecting works" — the one-time explainer shown immediately before the
 * user's FIRST enclave approval, and afterwards on demand from Settings.
 *
 * Placed here rather than at install time on purpose. An onboarding carousel
 * shown five screens before it matters is read by nobody; the same four cards
 * shown at the moment the wallet is about to ask "do you trust this?" are
 * answering a question the user is already holding.
 *
 * Card 2 carries the whole argument, and is the reason this exists: a padlock
 * proves WHO you reached, attestation proves WHAT is running. Everything else
 * is context around that one sentence. Deliberately no TEE, no quote, no
 * MRTD, no vendor names anywhere in the sequence — the mechanism belongs on
 * the approval screen behind "show what we checked", for the reader who wants
 * it.
 *
 * The fifth panel ("What to watch for") is NOT in the main sequence. An
 * explainer that only reassures teaches people to tap through, so the caveats
 * get their own screen, reachable from the last card and from Settings.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useCallback, useMemo, useRef, useState } from 'react';
import {
    Pressable,
    ScrollView,
    StyleSheet,
    useWindowDimensions,
    View as RNView,
    type NativeScrollEvent,
    type NativeSyntheticEvent,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { Text, View, usePalette, type Palette } from '@/components/Themed';

/** Glyph + i18n keys for one card. Order here IS the order on screen. */
const CARDS = [
    { icon: 'hand-left-outline', key: 'card1' },
    { icon: 'search-outline', key: 'card2' },
    { icon: 'lock-closed-outline', key: 'card3' },
    { icon: 'options-outline', key: 'card4' },
] as const;

export function FirstConnectExplainer({
    appName,
    onDone,
    onSkip,
}: {
    /**
     * The app being connected to, named on cards 1 and 3. When the caller has
     * no name yet (no store listing, or the standalone entry from Settings)
     * the copy falls back to a generic noun rather than showing a hostname
     * fragment, which reads as a glitch.
     */
    appName?: string;
    /** Finished the sequence: continue into the approval screen. */
    onDone: () => void;
    /**
     * Left early. Omitted in standalone mode, where the header's back button
     * is the way out and a "Skip" would have nothing to skip to.
     */
    onSkip?: () => void;
}) {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const { width } = useWindowDimensions();

    const scroller = useRef<ScrollView>(null);
    const [index, setIndex] = useState(0);
    const [watching, setWatching] = useState(false);

    const app = appName?.trim() || t('firstConnect.genericApp');
    const last = index === CARDS.length - 1;

    const goTo = useCallback(
        (next: number) => {
            const clamped = Math.max(0, Math.min(CARDS.length - 1, next));
            setIndex(clamped);
            scroller.current?.scrollTo({ x: clamped * width, animated: true });
        },
        [width],
    );

    // Keep the rail honest when the user swipes instead of tapping. Rounding
    // rather than flooring: a page settles a fraction of a pixel either side
    // of the boundary and flooring parks the rail one card behind.
    const onSettled = useCallback(
        (e: NativeSyntheticEvent<NativeScrollEvent>) => {
            setIndex(Math.round(e.nativeEvent.contentOffset.x / Math.max(width, 1)));
        },
        [width],
    );

    if (watching) {
        return <WhatToWatch onBack={() => setWatching(false)} styles={styles} insets={insets.bottom} />;
    }

    return (
        <RNView style={styles.screen}>
            {onSkip ? (
                <RNView style={[styles.topBar, { paddingTop: insets.top + 8 }]}>
                    <Pressable onPress={onSkip} hitSlop={12} accessibilityRole="button">
                        <Text style={styles.skip}>{t('firstConnect.skip')}</Text>
                    </Pressable>
                </RNView>
            ) : (
                <RNView style={{ height: 8 }} />
            )}

            <ScrollView
                ref={scroller}
                horizontal
                pagingEnabled
                showsHorizontalScrollIndicator={false}
                onMomentumScrollEnd={onSettled}
                style={styles.pager}
            >
                {CARDS.map((card) => (
                    <RNView key={card.key} style={[styles.page, { width }]}>
                        <View style={styles.glyphWrap}>
                            <Ionicons name={card.icon} size={30} color={p.green} />
                        </View>
                        <Text style={styles.cardTitle}>{t(`firstConnect.${card.key}Title`)}</Text>

                        {card.key === 'card2' ? (
                            // The contrast is the payload, so it gets structure
                            // rather than two paragraphs a reader can skim past.
                            <>
                                <View style={styles.contrastCard}>
                                    <Text style={styles.contrastLabel}>{t('firstConnect.card2WebLabel')}</Text>
                                    <Text style={styles.contrastBody}>{t('firstConnect.card2WebBody')}</Text>
                                </View>
                                <View style={[styles.contrastCard, styles.contrastCardHere]}>
                                    <Text style={[styles.contrastLabel, styles.contrastLabelHere]}>
                                        {t('firstConnect.card2HereLabel')}
                                    </Text>
                                    <Text style={styles.contrastBody}>{t('firstConnect.card2HereBody')}</Text>
                                </View>
                            </>
                        ) : (
                            <>
                                <Text style={styles.cardBody}>
                                    {t(`firstConnect.${card.key}Body`, { app })}
                                </Text>
                                {card.key === 'card3' || card.key === 'card4' ? (
                                    <Text style={styles.cardAside}>
                                        {t(`firstConnect.${card.key}Aside`, { app })}
                                    </Text>
                                ) : null}
                            </>
                        )}

                        {card.key === 'card4' ? (
                            <Pressable onPress={() => setWatching(true)} style={styles.watchLink} hitSlop={8}>
                                <Ionicons name="alert-circle-outline" size={16} color={p.action} />
                                <Text style={styles.watchLinkText}>{t('firstConnect.watchTitle')}</Text>
                                <Ionicons name="chevron-forward" size={15} color={p.action} />
                            </Pressable>
                        ) : null}
                    </RNView>
                ))}
            </ScrollView>

            <RNView style={styles.rail} accessibilityRole="progressbar">
                {CARDS.map((c, i) => (
                    <RNView key={c.key} style={[styles.railSeg, i <= index && styles.railSegOn]} />
                ))}
            </RNView>

            <RNView style={[styles.actions, { paddingBottom: Math.max(insets.bottom, 20) }]}>
                {index > 0 ? (
                    <Pressable style={[styles.button, styles.buttonNeutral]} onPress={() => goTo(index - 1)}>
                        <Text style={styles.buttonNeutralText}>{t('firstConnect.back')}</Text>
                    </Pressable>
                ) : null}
                <Pressable
                    style={[styles.button, styles.buttonGo, index > 0 && styles.buttonWide]}
                    onPress={() => (last ? onDone() : goTo(index + 1))}
                >
                    <Text style={styles.buttonGoText}>
                        {last
                            ? t('firstConnect.showApp')
                            : index === 0
                                ? t('firstConnect.start')
                                : t('firstConnect.next')}
                    </Text>
                </Pressable>
            </RNView>
        </RNView>
    );
}

/**
 * The caveats. Three items, each one thing the user can actually act on when
 * they next see the approval screen.
 */
function WhatToWatch({
    onBack,
    styles,
    insets,
}: {
    onBack: () => void;
    styles: ReturnType<typeof makeStyles>;
    insets: number;
}) {
    const { t } = useTranslation();
    const items = ['watch1', 'watch2', 'watch3'] as const;
    return (
        <RNView style={styles.screen}>
            <ScrollView contentContainerStyle={styles.watchContent}>
                <Text style={styles.cardTitle}>{t('firstConnect.watchTitle')}</Text>
                <Text style={styles.cardBody}>{t('firstConnect.watchIntro')}</Text>
                {items.map((key) => (
                    <View key={key} style={styles.watchItem}>
                        <Text style={styles.watchItemTitle}>{t(`firstConnect.${key}Title`)}</Text>
                        <Text style={styles.watchItemBody}>{t(`firstConnect.${key}Body`)}</Text>
                    </View>
                ))}
            </ScrollView>
            <RNView style={[styles.actions, { paddingBottom: Math.max(insets, 20) }]}>
                <Pressable style={[styles.button, styles.buttonGo]} onPress={onBack}>
                    <Text style={styles.buttonGoText}>{t('firstConnect.gotIt')}</Text>
                </Pressable>
            </RNView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    topBar: { paddingHorizontal: 20, paddingBottom: 4, alignItems: 'flex-end' },
    skip: { fontSize: 15, fontWeight: '500', color: p.textSecondary },

    pager: { flex: 1 },
    // No `flex` here. In a horizontal ScrollView the content container lays
    // out in a row, so flex-grow fights the fixed page width and the paging
    // snap lands mid-card. Height comes from the row's default stretch.
    page: { justifyContent: 'center', paddingHorizontal: 28, gap: 14 },

    glyphWrap: {
        width: 56,
        height: 56,
        borderRadius: 16,
        backgroundColor: p.successBg,
        alignItems: 'center',
        justifyContent: 'center',
        marginBottom: 2,
    },
    cardTitle: { fontSize: 25, fontWeight: '700', letterSpacing: -0.5, color: p.textPrimary, lineHeight: 31 },
    cardBody: { fontSize: 16, lineHeight: 24, color: p.textSecondary },
    cardAside: { fontSize: 14, lineHeight: 21, color: p.textMuted },

    contrastCard: {
        backgroundColor: p.card,
        borderRadius: 12,
        borderWidth: 1,
        borderColor: p.border,
        padding: 15,
        gap: 5,
    },
    contrastCardHere: { borderColor: p.successBorder, backgroundColor: p.successBg },
    contrastLabel: {
        fontSize: 11,
        fontWeight: '700',
        letterSpacing: 0.7,
        textTransform: 'uppercase',
        color: p.textMuted,
        backgroundColor: 'transparent',
    },
    contrastLabelHere: { color: p.successText },
    contrastBody: { fontSize: 14.5, lineHeight: 21, color: p.textSecondary, backgroundColor: 'transparent' },

    watchLink: { flexDirection: 'row', alignItems: 'center', gap: 6, marginTop: 6 },
    watchLinkText: { fontSize: 14.5, fontWeight: '600', color: p.action },

    watchContent: { paddingHorizontal: 28, paddingTop: 28, paddingBottom: 24, gap: 14 },
    watchItem: {
        backgroundColor: p.card,
        borderRadius: 12,
        borderWidth: 1,
        borderColor: p.border,
        padding: 15,
        gap: 5,
    },
    watchItemTitle: { fontSize: 15, fontWeight: '600', color: p.textPrimary, backgroundColor: 'transparent' },
    watchItemBody: { fontSize: 14, lineHeight: 21, color: p.textSecondary, backgroundColor: 'transparent' },

    rail: { flexDirection: 'row', gap: 6, paddingHorizontal: 28, paddingBottom: 14 },
    railSeg: { flex: 1, height: 3, borderRadius: 2, backgroundColor: p.border },
    railSegOn: { backgroundColor: p.green },

    actions: {
        flexDirection: 'row',
        gap: 10,
        paddingHorizontal: 20,
        paddingTop: 12,
        borderTopWidth: StyleSheet.hairlineWidth,
        borderTopColor: p.border,
        backgroundColor: p.screenBg,
    },
    button: { flex: 1, paddingVertical: 15, borderRadius: 12, alignItems: 'center' },
    buttonWide: { flex: 1.4 },
    buttonNeutral: { backgroundColor: p.buttonNeutral },
    buttonNeutralText: { fontSize: 16, fontWeight: '600', color: p.textPrimary },
    buttonGo: { backgroundColor: p.approve },
    buttonGoText: { fontSize: 16, fontWeight: '600', color: '#FFFFFF' },
});
