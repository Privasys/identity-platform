// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Drive tab — browse the caller's confidential personal drive.
 *
 * In progress (gated behind Settings → driveEnabled). On mount it ensures the
 * drive session (connect + setupPersonalDrive over RA-TLS) and lists the root
 * folder. Layout mirrors the Home tab's card list.
 */

import { Ionicons } from '@expo/vector-icons';
import { useEffect, useState } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import { ensureDrive, type DriveNode } from '@/services/drive';

function formatSize(bytes: number): string {
    if (!bytes) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function DriveScreen() {
    const insets = useSafeAreaInsets();
    const [nodes, setNodes] = useState<DriveNode[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);

    const load = async () => {
        setLoading(true);
        setError(null);
        try {
            const s = await ensureDrive();
            if (!s) {
                setError('Drive is not available on this deployment yet.');
                setNodes(null);
                return;
            }
            setNodes(await s.drive.listRoot(s.tenant.id));
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not open your drive.');
            setNodes(null);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        void load();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
        <RNView style={styles.screen}>
            <RNView style={[styles.header, { paddingTop: insets.top + 16 }]}>
                <Text style={styles.headerTitle}>Drive</Text>
                <Text style={styles.headerSubtitle}>Your confidential files</Text>
            </RNView>

            <RNView style={styles.content}>
                {loading ? (
                    <ActivityIndicator style={styles.spinner} size="large" color="#00BCF2" />
                ) : error ? (
                    <RNView style={styles.emptyState}>
                        <Ionicons name="cloud-offline-outline" size={44} color="#94A3B8" />
                        <Text style={styles.emptyText}>{error}</Text>
                        <Pressable style={styles.retry} onPress={() => void load()}>
                            <Text style={styles.retryText}>Try again</Text>
                        </Pressable>
                    </RNView>
                ) : nodes && nodes.length === 0 ? (
                    <RNView style={styles.emptyState}>
                        <Ionicons name="folder-open-outline" size={44} color="#94A3B8" />
                        <Text style={styles.emptyText}>Your drive is empty.</Text>
                    </RNView>
                ) : (
                    <ScrollView
                        contentContainerStyle={styles.list}
                        showsVerticalScrollIndicator={false}
                    >
                        {(nodes ?? []).map((n) => (
                            <RNView key={n.id} style={styles.card}>
                                <RNView
                                    style={[
                                        styles.icon,
                                        { backgroundColor: n.kind === 'folder' ? '#00BCF2' : '#8B5CF6' }
                                    ]}
                                >
                                    <Ionicons
                                        name={n.kind === 'folder' ? 'folder' : 'document'}
                                        size={18}
                                        color="#FFFFFF"
                                    />
                                </RNView>
                                <RNView style={styles.info}>
                                    <Text style={styles.name} numberOfLines={1}>
                                        {n.name}
                                    </Text>
                                    <Text style={styles.meta}>
                                        {n.kind === 'folder' ? 'Folder' : formatSize(n.size_bytes) || 'File'}
                                    </Text>
                                </RNView>
                            </RNView>
                        ))}
                    </ScrollView>
                )}
            </RNView>
        </RNView>
    );
}

const styles = StyleSheet.create({
    screen: { flex: 1, backgroundColor: '#F8FAFB' },
    header: {
        backgroundColor: '#34E89E',
        paddingHorizontal: 24,
        paddingBottom: 32,
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28
    },
    headerTitle: { fontSize: 28, fontWeight: '700', color: '#FFFFFF', letterSpacing: -0.5, marginBottom: 4 },
    headerSubtitle: { fontSize: 15, color: 'rgba(255,255,255,0.8)' },
    content: { flex: 1 },
    spinner: { marginTop: 60 },
    list: { padding: 20, paddingTop: 24, paddingBottom: 96 },
    emptyState: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 40, gap: 12 },
    emptyText: { fontSize: 15, textAlign: 'center', color: '#64748B', lineHeight: 22 },
    retry: {
        marginTop: 8,
        backgroundColor: '#00BCF2',
        borderRadius: 12,
        paddingHorizontal: 20,
        paddingVertical: 10
    },
    retryText: { color: '#FFFFFF', fontSize: 15, fontWeight: '600' },
    card: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 16,
        padding: 16,
        marginBottom: 10,
        shadowColor: '#0F172A',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.06,
        shadowRadius: 8,
        elevation: 2
    },
    icon: {
        width: 40,
        height: 40,
        borderRadius: 12,
        alignItems: 'center',
        justifyContent: 'center',
        marginRight: 14
    },
    info: { flex: 1 },
    name: { fontSize: 16, fontWeight: '600', color: '#0F172A' },
    meta: { fontSize: 12, color: '#64748B', marginTop: 2 }
});
