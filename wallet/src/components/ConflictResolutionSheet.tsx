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

import { Ionicons } from '@expo/vector-icons';
import { StyleSheet, Pressable, View as RNView } from 'react-native';

import { Text } from '@/components/Themed';
import type { ProfileAttribute } from '@/stores/profile';

export interface AttributeConflict {
    existing: ProfileAttribute;
    incoming: ProfileAttribute;
    multiValued: boolean;
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
    const { existing, incoming, multiValued } = conflict;
    return (
        <RNView style={styles.card}>
            <RNView style={styles.headerRow}>
                <Ionicons name="git-compare-outline" size={20} color="#F59E0B" />
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
                    <Text style={styles.optionValue}>{existing.value}</Text>
                    <Text style={styles.optionMeta}>Current {sourcesSummary(existing)}</Text>
                </RNView>
                <Ionicons name="chevron-forward" size={18} color="#94A3B8" />
            </Pressable>

            <Pressable style={styles.option} onPress={() => onResolve('replace')}>
                <RNView style={{ flex: 1 }}>
                    <Text style={styles.optionValue}>{incoming.value}</Text>
                    <Text style={styles.optionMeta}>New {sourcesSummary(incoming)}</Text>
                </RNView>
                <Ionicons name="chevron-forward" size={18} color="#94A3B8" />
            </Pressable>

            {multiValued && (
                <Pressable style={[styles.option, styles.bothOption]} onPress={() => onResolve('both')}>
                    <Ionicons name="albums-outline" size={18} color="#00BCF2" />
                    <Text style={styles.bothText}>Keep both</Text>
                </Pressable>
            )}
        </RNView>
    );
}

const styles = StyleSheet.create({
    card: { backgroundColor: '#FFFFFF', borderRadius: 14, padding: 16 },
    headerRow: { flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 6 },
    title: { flex: 1, fontSize: 16, fontWeight: '700', color: '#0F172A' },
    counter: { fontSize: 12, color: '#94A3B8', fontWeight: '600' },
    subtitle: { fontSize: 13, color: '#64748B', lineHeight: 18, marginBottom: 14 },
    option: {
        flexDirection: 'row', alignItems: 'center', gap: 10,
        backgroundColor: '#F8FAFB', borderRadius: 12, padding: 14, marginBottom: 8,
        borderWidth: 1, borderColor: '#E2E8F0',
    },
    optionValue: { fontSize: 15, fontWeight: '600', color: '#0F172A' },
    optionMeta: { fontSize: 12, color: '#94A3B8', marginTop: 2 },
    bothOption: { justifyContent: 'center', borderColor: '#BAE6FD', backgroundColor: '#F0F9FF' },
    bothText: { fontSize: 15, fontWeight: '600', color: '#00BCF2' },
});
