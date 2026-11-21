// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Conflict resolution sheet — shown during import when an incoming attribute has
 * a different value from one already stored under the same key (e.g. Google and
 * LinkedIn return different display-name casings). The user picks which value to
 * keep; for multi-valued attributes (email, phone) they can keep both.
 *
 * Conflicts are presented one at a time from a queue.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useMemo } from 'react';
import { StyleSheet, Pressable, View as RNView } from 'react-native';

import { Image, Text, usePalette, type Palette } from '@/components/Themed';
import { formatAddress } from '@/services/card-check';
import type { ProfileAttribute } from '@/stores/profile';

export interface AttributeConflict {
    existing: ProfileAttribute;
    incoming: ProfileAttribute;
    multiValued: boolean;
}

/** A value that is a picture (an avatar, a photo): shown, never spelled out. */
function isPicture(attr: ProfileAttribute): boolean {
    const v = attr.value.trim();
    return v.startsWith('data:image/') || (/picture|avatar|photo/i.test(attr.key) && /^https?:\/\//.test(v));
}

/** One option's value, the way the holder would recognise it. */
function OptionValue({ attr, styles }: { attr: ProfileAttribute; styles: ReturnType<typeof makeStyles> }) {
    if (isPicture(attr)) {
        return <Image source={{ uri: attr.value.trim() }} style={styles.picture} contentFit="cover" accessibilityIgnoresInvertColors />;
    }
    return (
        <Text style={styles.optionValue} numberOfLines={3}>
            {attr.key === 'address' ? formatAddress(attr.value) : attr.value}
        </Text>
    );
}

function sourcesSummary(attr: ProfileAttribute): string {
    const names = (attr.sources ?? []).map((s) => s.displayName);
    if (names.length === 0) return '';
    if (names.length === 1) return `from ${names[0]}`;
    return `from ${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

export function ConflictResolutionSheet({
    conflict,
    index,
    total,
    onResolve,
}: {
    conflict: AttributeConflict;
    index: number;
    total: number;
    onResolve: (choice: 'keep' | 'replace' | 'both') => void;
}) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { existing, incoming, multiValued } = conflict;
    return (
        <RNView style={styles.card}>
            <RNView style={styles.headerRow}>
                <Ionicons name="git-compare-outline" size={20} color={p.warnText} />
                <Text style={styles.title}>Conflicting {existing.label}</Text>
                {total > 1 && <Text style={styles.counter}>{index + 1} of {total}</Text>}
            </RNView>
            <Text style={styles.subtitle}>
                {multiValued
                    ? `You already have a ${existing.label.toLowerCase()}. Keep both, or pick one.`
                    : `This ${existing.label.toLowerCase()} differs from the one you already have. Which is correct?`}
            </Text>

            <Pressable style={styles.option} onPress={() => onResolve('keep')}>
                <RNView style={{ flex: 1 }}>
                    <OptionValue attr={existing} styles={styles} />
                    <Text style={styles.optionMeta}>Current {sourcesSummary(existing)}</Text>
                </RNView>
                <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
            </Pressable>

            <Pressable style={styles.option} onPress={() => onResolve('replace')}>
                <RNView style={{ flex: 1 }}>
                    <OptionValue attr={incoming} styles={styles} />
                    <Text style={styles.optionMeta}>New {sourcesSummary(incoming)}</Text>
                </RNView>
                <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
            </Pressable>

            {multiValued && (
                <Pressable style={[styles.option, styles.bothOption]} onPress={() => onResolve('both')}>
                    <Ionicons name="albums-outline" size={18} color={p.blue} />
                    <Text style={styles.bothText}>Keep both</Text>
                </Pressable>
            )}
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    card: { backgroundColor: p.card, borderRadius: 14, padding: 16 },
    headerRow: { flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 6 },
    title: { flex: 1, fontSize: 16, fontWeight: '700', color: p.textPrimary },
    counter: { fontSize: 12, color: p.textMuted, fontWeight: '600' },
    subtitle: { fontSize: 13, color: p.textSecondary, lineHeight: 18, marginBottom: 14 },
    option: {
        flexDirection: 'row', alignItems: 'center', gap: 10,
        backgroundColor: p.screenBg, borderRadius: 12, padding: 14, marginBottom: 8,
        borderWidth: 1, borderColor: p.border,
    },
    optionValue: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
    picture: { width: 64, height: 64, borderRadius: 32, backgroundColor: p.border },
    optionMeta: { fontSize: 12, color: p.textMuted, marginTop: 2 },
    bothOption: { justifyContent: 'center', borderColor: p.infoBorder, backgroundColor: p.infoBg },
    bothText: { fontSize: 15, fontWeight: '600', color: p.blue },
});
