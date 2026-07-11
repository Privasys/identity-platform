// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Import selection sheet — after linking a provider, lets the user choose which
 * of the returned attributes to import. Everything is ticked by default (import
 * all user attributes), but the user stays in control and can untick any (e.g.
 * the avatar) before confirming.
 */

import { Ionicons } from '@expo/vector-icons';
import { useMemo } from 'react';
import { Image, Pressable, StyleSheet, Switch, View as RNView } from 'react-native';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { attributeLabel } from '@/services/attributes';
import type { ProfileAttribute } from '@/stores/profile';

export function ImportSelectionSheet({
    providerName,
    attributes,
    selected,
    onToggle,
    onConfirm,
    onCancel,
    busy,
}: {
    providerName: string;
    attributes: ProfileAttribute[];
    selected: Set<string>;
    onToggle: (key: string) => void;
    onConfirm: () => void;
    onCancel: () => void;
    busy?: boolean;
}) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const count = attributes.filter((a) => selected.has(a.key)).length;
    return (
        <RNView style={styles.card}>
            <Text style={styles.title}>Import from {providerName}</Text>
            <Text style={styles.subtitle}>
                Choose what to add to your profile. Everything is selected by default — untick
                anything you'd rather not import.
            </Text>

            {attributes.map((attr) => {
                const isOn = selected.has(attr.key);
                return (
                    <Pressable key={attr.key} style={styles.row} onPress={() => onToggle(attr.key)}>
                        {(attr.key === 'picture' || attr.key === 'picture_id') && attr.value ? (
                            <Image source={{ uri: attr.value }} style={styles.avatar} />
                        ) : (
                            <RNView style={styles.iconCircle}>
                                <Ionicons name={iconFor(attr.key)} size={16} color={p.textSecondary} />
                            </RNView>
                        )}
                        <RNView style={styles.rowInfo}>
                            <Text style={styles.rowLabel}>{attributeLabel(attr.key)}</Text>
                            <Text style={styles.rowValue} numberOfLines={1}>
                                {attr.key === 'picture' ? 'Profile photo'
                                    : attr.key === 'picture_id' ? 'ID photo'
                                    : attr.value}
                                {attr.verified ? '  ·  verified' : ''}
                            </Text>
                        </RNView>
                        <Switch value={isOn} onValueChange={() => onToggle(attr.key)} />
                    </Pressable>
                );
            })}

            <Pressable
                style={[styles.confirm, (count === 0 || busy) && styles.confirmDisabled]}
                onPress={onConfirm}
                disabled={count === 0 || busy}
            >
                <Text style={styles.confirmText}>
                    {count === 0 ? 'Select at least one' : `Import ${count} attribute${count !== 1 ? 's' : ''}`}
                </Text>
            </Pressable>
            <Pressable style={styles.cancel} onPress={onCancel} disabled={busy}>
                <Text style={styles.cancelText}>Cancel</Text>
            </Pressable>
        </RNView>
    );
}

function iconFor(key: string): keyof typeof Ionicons.glyphMap {
    switch (key) {
        case 'email': return 'mail-outline';
        case 'name': return 'person-outline';
        case 'given_name':
        case 'family_name': return 'text-outline';
        case 'locale': return 'language-outline';
        case 'phone_number': return 'call-outline';
        default: return 'ellipse-outline';
    }
}

const makeStyles = (p: Palette) => StyleSheet.create({
    card: { backgroundColor: p.card, borderRadius: 16, padding: 16, marginTop: 8 },
    title: { fontSize: 17, fontWeight: '700', color: p.textPrimary },
    subtitle: { fontSize: 13, color: p.textSecondary, lineHeight: 19, marginTop: 4, marginBottom: 12 },
    row: {
        flexDirection: 'row', alignItems: 'center', gap: 12, paddingVertical: 10,
        borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: p.border,
    },
    iconCircle: {
        width: 32, height: 32, borderRadius: 16, backgroundColor: p.cardAlt,
        alignItems: 'center', justifyContent: 'center',
    },
    avatar: { width: 32, height: 32, borderRadius: 16, backgroundColor: p.cardAlt },
    rowInfo: { flex: 1 },
    rowLabel: { fontSize: 15, fontWeight: '500', color: p.textPrimary },
    rowValue: { fontSize: 12, color: p.textMuted, marginTop: 1 },
    confirm: {
        backgroundColor: p.blue, borderRadius: 12, paddingVertical: 14,
        alignItems: 'center', marginTop: 16,
    },
    confirmDisabled: { opacity: 0.5 },
    confirmText: { color: '#FFFFFF', fontSize: 15, fontWeight: '600' },
    cancel: { paddingVertical: 12, alignItems: 'center' },
    cancelText: { color: p.textSecondary, fontSize: 14 },
});
