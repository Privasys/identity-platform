// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Export Data sub-page. The user picks which attributes to export (all selected
 * by default) and shares a signed-provenance JSON, or exports everything.
 */

import { Ionicons } from '@expo/vector-icons';
import { File, Paths } from 'expo-file-system';
import * as Sharing from 'expo-sharing';
import { useMemo, useState } from 'react';
import { Alert, Pressable, ScrollView, StyleSheet, Switch, View as RNView } from 'react-native';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { attributeLabel, exportAttributesForAudit } from '@/services/attributes';
import { useProfileStore } from '@/stores/profile';

export default function ExportDataScreen() {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { profile } = useProfileStore();
    const attrs = profile?.attributes ?? [];
    const [selected, setSelected] = useState<Set<string>>(() => new Set(attrs.map((a) => a.key)));

    const toggle = (key: string) =>
        setSelected((prev) => {
            const next = new Set(prev);
            if (next.has(key)) next.delete(key);
            else next.add(key);
            return next;
        });

    const doExport = async (keys: Set<string>) => {
        if (!profile) return;
        try {
            const data = exportAttributesForAudit(profile);
            data.attributes = data.attributes.filter((a) => keys.has(a.key));
            const json = JSON.stringify(data, null, 2);
            const file = new File(Paths.cache, `privasys-profile-${Date.now()}.json`);
            file.write(json);
            await Sharing.shareAsync(file.uri, {
                mimeType: 'application/json',
                dialogTitle: 'Export Profile Data',
                UTI: 'public.json',
            });
        } catch (e: any) {
            Alert.alert('Export failed', e.message);
        }
    };

    const count = attrs.filter((a) => selected.has(a.key)).length;

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title="Export Data" />
            <ScrollView contentContainerStyle={styles.content}>
                <Text style={styles.intro}>
                    Export your attributes as a JSON file with their provenance and verification
                    history. Choose what to include, or export everything.
                </Text>

                {attrs.length === 0 ? (
                    <Text style={styles.empty}>No attributes to export yet.</Text>
                ) : (
                    <>
                        {attrs.map((attr) => (
                            <Pressable key={attr.key} style={styles.row} onPress={() => toggle(attr.key)}>
                                <RNView style={{ flex: 1 }}>
                                    <Text style={styles.rowLabel}>{attributeLabel(attr.key)}</Text>
                                    <Text style={styles.rowValue} numberOfLines={1}>
                                        {attr.key === 'picture' ? 'Profile photo' : attr.value}
                                    </Text>
                                </RNView>
                                <Switch value={selected.has(attr.key)} onValueChange={() => toggle(attr.key)} />
                            </Pressable>
                        ))}

                        <Pressable
                            style={[styles.primary, count === 0 && styles.disabled]}
                            onPress={() => doExport(selected)}
                            disabled={count === 0}
                        >
                            <Ionicons name="share-outline" size={18} color="#FFFFFF" />
                            <Text style={styles.primaryText}>
                                Export {count} attribute{count !== 1 ? 's' : ''}
                            </Text>
                        </Pressable>
                        <Pressable style={styles.secondary} onPress={() => doExport(new Set(attrs.map((a) => a.key)))}>
                            <Text style={styles.secondaryText}>Export all</Text>
                        </Pressable>
                    </>
                )}
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    content: { padding: 20 },
    intro: { fontSize: 14, color: p.textSecondary, lineHeight: 20, marginBottom: 16 },
    empty: { fontSize: 14, color: p.textMuted, textAlign: 'center', marginTop: 16 },
    row: {
        flexDirection: 'row', alignItems: 'center', gap: 12, backgroundColor: p.card,
        borderRadius: 12, paddingHorizontal: 16, paddingVertical: 12, marginBottom: 8,
    },
    rowLabel: { fontSize: 15, fontWeight: '500', color: p.textPrimary },
    rowValue: { fontSize: 12, color: p.textMuted, marginTop: 1 },
    primary: {
        flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8,
        backgroundColor: p.blue, borderRadius: 12, paddingVertical: 14, marginTop: 12,
    },
    primaryText: { color: '#FFFFFF', fontSize: 15, fontWeight: '600' },
    disabled: { opacity: 0.5 },
    secondary: { paddingVertical: 12, alignItems: 'center' },
    secondaryText: { color: p.blue, fontSize: 14, fontWeight: '500' },
});
