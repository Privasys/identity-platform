// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Settings -> Language.
 *
 * A pushed screen rather than an inline list: there are 26 choices, and
 * rendering them in Settings buried every other setting under a wall of rows.
 *
 * Languages are listed as ENDONYMS ("Deutsch", not "German") because someone
 * looking for their own language cannot necessarily read the one currently on
 * screen. Same convention as shared/referential/locale.json. The English name
 * is shown underneath so the list is still navigable by someone helping a user
 * who has landed in a language they cannot read.
 *
 * Selecting a language downloads its pack (~25KB) unless it is already on the
 * device. That can fail, and the failure is shown rather than swallowed: the
 * wallet stays on the language it had, and the row stops showing a spinner.
 * A pack that fails its digest check gets a DIFFERENT message from one that
 * simply would not download, because the two mean very different things (see
 * i18n/packs.ts).
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { Stack, useRouter } from 'expo-router';
import { useCallback, useMemo, useState } from 'react';
import {
    ActivityIndicator,
    Alert,
    Pressable,
    ScrollView,
    StyleSheet,
    View as RNView,
} from 'react-native';
import { useTranslation } from 'react-i18next';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text, View, usePalette, type Palette } from '@/components/Themed';
import { applyLocale } from '@/i18n';
import { SUPPORTED_LOCALES, localeMeta } from '@/i18n/locales';
import { isPackAvailable } from '@/i18n/packs';
import { useSettingsStore } from '@/stores/settings';

/** Tags usable without a download. Recomputed only when one is added. */
function availableTags(): Set<string> {
    return new Set(SUPPORTED_LOCALES.filter((l) => isPackAvailable(l.tag)).map((l) => l.tag));
}

export default function LanguageScreen() {
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);

    // `i18n.language` rather than a module read: useTranslation re-renders on
    // languageChanged, so this is the only spelling of "current language" that
    // cannot go stale under the component.
    const { t, i18n } = useTranslation();
    const active = i18n.language;

    const language = useSettingsStore((s) => s.language);
    const setLanguage = useSettingsStore((s) => s.setLanguage);
    const [pending, setPending] = useState<string | null>(null);
    // Held in state, not recomputed per render: a download changes it exactly
    // once, and the alternative is 25 filesystem hits every time this list
    // paints.
    const [available, setAvailable] = useState<Set<string>>(availableTags);

    const choose = useCallback(
        async (tag: string | null) => {
            if (pending) return;
            const previous = active;

            // "Use device language" resolves through the same negotiation the
            // app uses at launch, so it can also need a download.
            setPending(tag ?? 'system');
            const result = await applyLocale(tag ?? undefined);
            setPending(null);

            if (!result.ok) {
                const name = localeMeta(tag ?? '')?.endonym ?? tag ?? '';
                const current = localeMeta(previous)?.endonym ?? previous;
                // A rejected pack is not a network problem and must not read
                // like one: it means the bytes served were not the bytes this
                // build is signed to accept.
                const key = result.reason === 'rejected' ? 'verificationFailed' : 'downloadFailed';
                Alert.alert(
                    t(`language.${key}Title`),
                    t(`language.${key}Body`, { language: name, current }),
                );
                return;
            }
            setLanguage(tag);
            // A first-time selection just wrote a pack to disk.
            setAvailable(availableTags());
        },
        [active, pending, setLanguage, t],
    );

    return (
        <RNView style={styles.screen}>
            <Stack.Screen options={{ headerShown: false }} />
            <RNView style={[styles.header, { paddingTop: insets.top + 12 }]}>
                <Pressable onPress={() => router.back()} style={styles.backButton} hitSlop={10}>
                    <Ionicons name="chevron-back" size={24} color="#FFFFFF" />
                </Pressable>
                <Text style={styles.headerTitle}>{t('language.title')}</Text>
            </RNView>

            <ScrollView style={styles.scroll} contentContainerStyle={styles.content}>
                <Text style={styles.description}>{t('language.description')}</Text>

                <View style={styles.card}>
                    <LanguageRow
                        label={t('language.systemDefault')}
                        selected={language === null}
                        busy={pending === 'system'}
                        onPress={() => void choose(null)}
                        styles={styles}
                        p={p}
                    />
                    {SUPPORTED_LOCALES.map((locale) => (
                        <LanguageRow
                            key={locale.tag}
                            label={locale.endonym}
                            hint={locale.english}
                            downloaded={available.has(locale.tag)}
                            selected={language === locale.tag}
                            // When the preference is "use device language" the
                            // tick sits on that row, so without this the
                            // language actually on screen would be the one row
                            // with nothing to say for itself.
                            inUse={locale.tag === active}
                            busy={pending === locale.tag}
                            onPress={() => void choose(locale.tag)}
                            styles={styles}
                            p={p}
                        />
                    ))}
                </View>

                <Text style={styles.footnote}>{t('language.offlineNotice')}</Text>
            </ScrollView>
        </RNView>
    );
}

/**
 * Every row says one of four things, and none of them is silence:
 *
 *   spinner  the pack is downloading right now
 *   ✓        this is your choice
 *   ●        this is what you are reading, but not what you chose (you chose
 *            "use device language" and it resolved here)
 *   ☁        tapping this needs a download first
 *
 * A downloaded-but-unselected language previously fell through all of these
 * and rendered nothing, which read as "this one is broken".
 */
function LanguageRow({
    label,
    hint,
    downloaded,
    selected,
    inUse,
    busy,
    onPress,
    styles,
    p,
}: {
    label: string;
    hint?: string;
    downloaded?: boolean;
    selected: boolean;
    inUse?: boolean;
    busy: boolean;
    onPress: () => void;
    styles: ReturnType<typeof makeStyles>;
    p: Palette;
}) {
    return (
        <Pressable
            style={styles.row}
            onPress={onPress}
            disabled={busy}
            accessibilityRole="radio"
            accessibilityState={{ selected: selected || !!inUse }}
            accessibilityLabel={label}
        >
            <View style={styles.rowText}>
                <Text style={[styles.rowLabel, (selected || inUse) && styles.rowLabelActive]}>
                    {label}
                </Text>
                {hint ? <Text style={styles.rowHint}>{hint}</Text> : null}
            </View>
            {busy ? (
                <ActivityIndicator size="small" color={p.textSecondary} />
            ) : selected ? (
                <Ionicons name="checkmark" size={20} color={p.action} />
            ) : inUse ? (
                <Ionicons name="ellipse" size={9} color={p.action} />
            ) : downloaded ? (
                <Ionicons name="cloud-done-outline" size={17} color={p.textMuted} />
            ) : (
                <Ionicons name="cloud-download-outline" size={17} color={p.textMuted} />
            )}
        </Pressable>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    header: {
        backgroundColor: p.green,
        paddingHorizontal: 24,
        paddingBottom: 20,
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28,
    },
    backButton: { marginBottom: 8 },
    headerTitle: { fontSize: 28, fontWeight: '700', color: '#FFFFFF', letterSpacing: -0.5 },
    scroll: { flex: 1 },
    content: { paddingHorizontal: 20, paddingTop: 16, paddingBottom: 40 },
    description: {
        fontSize: 14,
        color: p.textSecondary,
        marginBottom: 14,
        lineHeight: 20,
    },
    card: {
        backgroundColor: p.card,
        borderRadius: 12,
        paddingHorizontal: 14,
    },
    row: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12,
        paddingVertical: 12,
    },
    rowText: { flex: 1, backgroundColor: 'transparent' },
    rowLabel: { fontSize: 15, fontWeight: '500', color: p.textPrimary },
    rowLabelActive: { color: p.action },
    rowHint: { fontSize: 12, color: p.textMuted, marginTop: 2 },
    footnote: {
        fontSize: 12,
        color: p.textMuted,
        marginTop: 14,
        lineHeight: 18,
    },
});
