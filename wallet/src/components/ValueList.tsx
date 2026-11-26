// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A searchable list of the values a coded attribute can take (a country, a
 * language), named in the holder's language. The code is what is stored and
 * shared; the holder only ever sees the long name.
 *
 * The list comes from privasys.id (services/value-sets), one copy per
 * language, so the wallet carries none of it. Rows look like the Language
 * screen's (routes/language.tsx): a card of rows, the chosen one ticked.
 * Used full screen from Personal Data (routes/attribute-value.tsx) and inside
 * the sign-in form's picker sheet (routes/connect.tsx).
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, FlatList, Pressable, StyleSheet, TextInput, View as RNView } from 'react-native';
import { useTranslation } from 'react-i18next';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { getAttributeValues, type ValueOption } from '@/services/value-sets';

/** Lower case without accents, so "cote" finds "Côte d'Ivoire". */
const fold = (s: string) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();

export function ValueList({
    attrKey,
    selected,
    onSelect,
    bottomInset = 0,
}: {
    attrKey: string;
    selected?: string;
    onSelect: (option: ValueOption) => void;
    bottomInset?: number;
}) {
    const { t, i18n } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const [options, setOptions] = useState<ValueOption[] | null>(null);
    const [query, setQuery] = useState('');
    const [attempt, setAttempt] = useState(0);

    useEffect(() => {
        let live = true;
        setOptions(null);
        void getAttributeValues(attrKey, i18n.language).then((v) => { if (live) setOptions(v); });
        return () => { live = false; };
    }, [attrKey, i18n.language, attempt]);

    const shown = useMemo(() => {
        if (!options) return [];
        const q = fold(query.trim());
        if (!q) return options;
        // A typed code finds its entry too ("FR", "en-GB").
        return options.filter((o) => fold(o.label).includes(q) || fold(o.value) === q);
    }, [options, query]);

    if (!options) {
        return (
            <RNView style={styles.centre}>
                <ActivityIndicator color={p.textSecondary} />
            </RNView>
        );
    }
    if (options.length === 0) {
        return (
            <RNView style={styles.centre}>
                <Text style={styles.message}>{t('personalData.listUnavailable')}</Text>
                <Pressable onPress={() => setAttempt((n) => n + 1)} hitSlop={8}>
                    <Text style={styles.retry}>{t('common.retry')}</Text>
                </Pressable>
            </RNView>
        );
    }

    return (
        <RNView style={styles.container}>
            <RNView style={styles.search}>
                <Ionicons name="search" size={16} color={p.textMuted} />
                <TextInput
                    style={styles.searchInput}
                    value={query}
                    onChangeText={setQuery}
                    placeholder={t('common.search')}
                    placeholderTextColor={p.textMuted}
                    autoCorrect={false}
                    autoComplete="off"
                    autoCapitalize="none"
                    returnKeyType="search"
                    clearButtonMode="while-editing"
                />
            </RNView>
            <FlatList
                style={styles.card}
                data={shown}
                keyExtractor={(o) => o.value}
                keyboardShouldPersistTaps="handled"
                initialNumToRender={20}
                contentContainerStyle={{ paddingBottom: bottomInset }}
                ListEmptyComponent={<Text style={styles.message}>{t('personalData.noMatch', { query: query.trim() })}</Text>}
                renderItem={({ item }) => {
                    const isSelected = !!selected && item.value.toUpperCase() === selected.toUpperCase();
                    return (
                        <Pressable
                            style={styles.row}
                            onPress={() => onSelect(item)}
                            accessibilityRole="radio"
                            accessibilityState={{ selected: isSelected }}
                            accessibilityLabel={item.label}
                        >
                            <Text style={[styles.rowLabel, isSelected && styles.rowLabelActive]}>{item.label}</Text>
                            {isSelected ? <Ionicons name="checkmark" size={20} color={p.action} /> : null}
                        </Pressable>
                    );
                }}
            />
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    container: { flex: 1 },
    centre: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 12, padding: 24 },
    search: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 8,
        backgroundColor: p.card,
        borderRadius: 12,
        paddingHorizontal: 14,
        marginBottom: 12,
    },
    searchInput: { flex: 1, fontSize: 15, color: p.textPrimary, paddingVertical: 12 },
    card: { flex: 1, backgroundColor: p.card, borderRadius: 12, paddingHorizontal: 14 },
    row: { flexDirection: 'row', alignItems: 'center', gap: 12, paddingVertical: 12 },
    rowLabel: { flex: 1, fontSize: 15, fontWeight: '500', color: p.textPrimary },
    rowLabelActive: { color: p.action },
    message: { fontSize: 14, color: p.textSecondary, textAlign: 'center', paddingVertical: 16 },
    retry: { fontSize: 15, fontWeight: '600', color: p.action },
});
