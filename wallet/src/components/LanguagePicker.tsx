// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Settings -> Language.
 *
 * Languages are listed as ENDONYMS ("Deutsch", not "German") because someone
 * looking for their own language cannot necessarily read the one currently on
 * screen. Same convention as shared/referential/locale.json.
 *
 * Selecting a language downloads its pack (~25KB) unless it is already on the
 * device. That can fail, and the failure is shown rather than swallowed: the
 * wallet stays on the language it had, and the row stops showing a spinner.
 * A pack that fails its digest check gets a DIFFERENT message from one that
 * simply would not download, because the two mean very different things (see
 * i18n/packs.ts).
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useCallback, useMemo, useState } from 'react';
import { ActivityIndicator, Alert, Pressable, StyleSheet } from 'react-native';
import { useTranslation } from 'react-i18next';

import { Text, View, usePalette, type Palette } from '@/components/Themed';
import { applyLocale, currentLocale } from '@/i18n';
import { SUPPORTED_LOCALES, localeMeta } from '@/i18n/locales';
import { isPackCached } from '@/i18n/packs';
import { useSettingsStore } from '@/stores/settings';

export function LanguagePicker() {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { t } = useTranslation();

    const language = useSettingsStore((s) => s.language);
    const setLanguage = useSettingsStore((s) => s.setLanguage);
    const [pending, setPending] = useState<string | null>(null);

    const active = currentLocale();

    const choose = useCallback(
        async (tag: string | null) => {
            if (pending) return;
            const previous = active;

            // "Use device language" resolves through the same negotiation the
            // app uses at launch, so it can also need a download.
            setPending(tag ?? 'system');
            const ok = await applyLocale(tag ?? undefined);
            setPending(null);

            if (!ok) {
                const name = localeMeta(tag ?? '')?.endonym ?? tag ?? '';
                const current = localeMeta(previous)?.endonym ?? previous;
                Alert.alert(
                    t('language.downloadFailedTitle'),
                    t('language.downloadFailedBody', { language: name, current }),
                );
                return;
            }
            setLanguage(tag);
        },
        [active, pending, setLanguage, t],
    );

    return (
        <>
            <Text style={styles.sectionTitle}>{t('language.title')}</Text>
            <Text style={styles.sectionDescription}>{t('language.description')}</Text>

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
                        // English is compiled in; everything else needs a pack.
                        hint={isPackCached(locale.tag) ? undefined : locale.english}
                        selected={language === locale.tag}
                        busy={pending === locale.tag}
                        onPress={() => void choose(locale.tag)}
                        styles={styles}
                        p={p}
                    />
                ))}
            </View>
        </>
    );
}

function LanguageRow({
    label,
    hint,
    selected,
    busy,
    onPress,
    styles,
    p,
}: {
    label: string;
    hint?: string;
    selected: boolean;
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
            accessibilityState={{ selected }}
            accessibilityLabel={label}
        >
            <View style={styles.rowText}>
                <Text style={styles.rowLabel}>{label}</Text>
                {hint ? <Text style={styles.rowHint}>{hint}</Text> : null}
            </View>
            {busy ? (
                <ActivityIndicator size="small" color={p.textSecondary} />
            ) : selected ? (
                <Ionicons name="checkmark" size={20} color={p.action} />
            ) : null}
        </Pressable>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    sectionTitle: {
        fontSize: 17,
        fontWeight: '600',
        color: p.textPrimary,
        marginTop: 24,
        marginBottom: 6,
    },
    sectionDescription: {
        fontSize: 14,
        color: p.textSecondary,
        marginBottom: 14,
        lineHeight: 20,
    },
    card: {
        backgroundColor: p.card,
        borderRadius: 12,
        paddingHorizontal: 14,
        marginBottom: 8,
    },
    row: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12,
        paddingVertical: 12,
    },
    rowText: { flex: 1, backgroundColor: 'transparent' },
    rowLabel: { fontSize: 15, fontWeight: '500', color: p.textPrimary },
    rowHint: { fontSize: 12, color: p.textMuted, marginTop: 2 },
});
