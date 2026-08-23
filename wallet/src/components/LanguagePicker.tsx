// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The Language row in Settings: one line showing the language in use, which
 * opens the full list at routes/language.tsx.
 *
 * Deliberately not an inline list. There are 26 choices, and rendering them
 * here pushed every other setting off the screen.
 *
 * The value shown is the ENDONYM of the language actually in effect, not the
 * stored preference: when the preference is "use device language" the user
 * still wants to see which language that resolved to.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useMemo } from 'react';
import { Pressable, StyleSheet } from 'react-native';
import { useTranslation } from 'react-i18next';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { currentLocale } from '@/i18n';
import { localeMeta } from '@/i18n/locales';
import { useSettingsStore } from '@/stores/settings';

export function LanguagePicker() {
    const router = useRouter();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { t } = useTranslation();

    const language = useSettingsStore((s) => s.language);
    const active = currentLocale();
    const endonym = localeMeta(active)?.endonym ?? active;

    // Following the device is a distinct state worth surfacing, so say so and
    // name what it currently resolves to.
    const value = language === null ? `${t('language.systemDefault')} (${endonym})` : endonym;

    return (
        <>
            <Text style={styles.sectionTitle}>{t('language.title')}</Text>
            <Pressable
                style={styles.row}
                onPress={() => router.push('/language')}
                accessibilityRole="button"
                accessibilityLabel={`${t('language.title')}: ${value}`}
            >
                <Ionicons name="language-outline" size={18} color={p.textPrimary} />
                <Text style={styles.value} numberOfLines={1}>
                    {value}
                </Text>
                <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
            </Pressable>
        </>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    sectionTitle: {
        fontSize: 17,
        fontWeight: '600',
        color: p.textPrimary,
        marginTop: 24,
        marginBottom: 10,
    },
    row: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        backgroundColor: p.card,
        borderRadius: 12,
        paddingHorizontal: 14,
        paddingVertical: 14,
    },
    value: { flex: 1, fontSize: 15, fontWeight: '500', color: p.textPrimary },
});
