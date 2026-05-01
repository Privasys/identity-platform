// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Logs viewer — surfaces the in-memory ring buffer captured by
 * {@link installLogCapture}. Exposes Copy and Export-to-File actions
 * so users on platforms without a system Console (notably iOS users
 * on Windows) can hand-share logs when reporting issues.
 */

import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import * as FileSystem from 'expo-file-system/legacy';
import { useRouter, Stack } from 'expo-router';
import * as Sharing from 'expo-sharing';
import { useState, useCallback } from 'react';
import { Alert, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text, View } from '@/components/Themed';
import { buildLogExport, clearLogs, formatLogs, getLogs } from '@/utils/logs';

export default function LogsScreen() {
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const [refreshKey, setRefreshKey] = useState(0);
    const entries = getLogs();
    const text = formatLogs(entries);

    const onCopy = useCallback(async () => {
        await Clipboard.setStringAsync(buildLogExport());
        Alert.alert('Copied', 'Logs copied to clipboard.');
    }, []);

    const onExport = useCallback(async () => {
        try {
            const filename = `privasys-wallet-logs-${Date.now()}.txt`;
            const path = `${FileSystem.cacheDirectory}${filename}`;
            await FileSystem.writeAsStringAsync(path, buildLogExport(), {
                encoding: FileSystem.EncodingType.UTF8,
            });
            if (await Sharing.isAvailableAsync()) {
                await Sharing.shareAsync(path, {
                    mimeType: 'text/plain',
                    dialogTitle: 'Export Wallet Logs',
                    UTI: 'public.plain-text',
                });
            } else {
                Alert.alert('Saved', `Logs written to ${path}`);
            }
        } catch (e: any) {
            Alert.alert('Export failed', e?.message ?? String(e));
        }
    }, []);

    const onClear = useCallback(() => {
        Alert.alert('Clear logs?', 'This removes all captured log entries from memory.', [
            { text: 'Cancel', style: 'cancel' },
            {
                text: 'Clear',
                style: 'destructive',
                onPress: () => {
                    clearLogs();
                    setRefreshKey((k) => k + 1);
                },
            },
        ]);
    }, []);

    return (
        <RNView style={styles.screen}>
            <Stack.Screen options={{ headerShown: false }} />
            <RNView style={[styles.header, { paddingTop: insets.top + 12 }]}>
                <Pressable onPress={() => router.back()} style={styles.backButton} hitSlop={10}>
                    <Ionicons name="chevron-back" size={24} color="#FFFFFF" />
                </Pressable>
                <Text style={styles.headerTitle}>Logs</Text>
                <Text style={styles.headerCount}>{entries.length} entries</Text>
            </RNView>

            <RNView style={styles.actionsRow}>
                <Pressable style={styles.actionButton} onPress={onCopy}>
                    <Ionicons name="copy-outline" size={16} color="#0F172A" />
                    <Text style={styles.actionText}>Copy</Text>
                </Pressable>
                <Pressable style={styles.actionButton} onPress={onExport}>
                    <Ionicons name="share-outline" size={16} color="#0F172A" />
                    <Text style={styles.actionText}>Export</Text>
                </Pressable>
                <Pressable style={[styles.actionButton, styles.actionButtonDanger]} onPress={onClear}>
                    <Ionicons name="trash-outline" size={16} color="#FF3B30" />
                    <Text style={[styles.actionText, styles.actionTextDanger]}>Clear</Text>
                </Pressable>
            </RNView>

            <ScrollView
                key={refreshKey}
                style={styles.scroll}
                contentContainerStyle={styles.content}
            >
                {entries.length === 0 ? (
                    <View style={styles.emptyCard}>
                        <Ionicons name="document-text-outline" size={32} color="#C7C7CC" />
                        <Text style={styles.emptyText}>No log entries yet</Text>
                    </View>
                ) : (
                    <Text style={styles.logText} selectable>
                        {text}
                    </Text>
                )}
            </ScrollView>
        </RNView>
    );
}

const styles = StyleSheet.create({
    screen: { flex: 1, backgroundColor: '#F8FAFB' },
    header: {
        backgroundColor: '#34E89E',
        paddingHorizontal: 24,
        paddingBottom: 20,
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28,
    },
    backButton: { marginBottom: 8 },
    headerTitle: { fontSize: 28, fontWeight: '700', color: '#FFFFFF', letterSpacing: -0.5 },
    headerCount: { fontSize: 13, color: '#FFFFFFCC', marginTop: 4 },
    actionsRow: {
        flexDirection: 'row',
        gap: 8,
        paddingHorizontal: 20,
        paddingVertical: 12,
    },
    actionButton: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        paddingVertical: 10,
        borderRadius: 10,
        backgroundColor: '#FFFFFF',
        borderWidth: 1,
        borderColor: '#E2E8F0',
    },
    actionButtonDanger: { borderColor: '#FECACA' },
    actionText: { fontSize: 14, fontWeight: '600', color: '#0F172A' },
    actionTextDanger: { color: '#FF3B30' },
    scroll: { flex: 1 },
    content: { padding: 16, paddingBottom: 40 },
    emptyCard: {
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 32,
        gap: 8,
    },
    emptyText: { fontSize: 14, color: '#C7C7CC' },
    logText: {
        fontSize: 11,
        fontFamily: 'SpaceMono',
        color: '#0F172A',
        lineHeight: 16,
    },
});
