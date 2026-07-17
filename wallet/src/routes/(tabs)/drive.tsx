// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Drive tab — browse the caller's confidential personal drive.
 *
 * Gated behind Settings → driveEnabled. The enclave resolves like the
 * identity verifier (store resolve API with hardcoded build fallback,
 * attestation-pinned either way); on mount the tab ensures the drive
 * session (connect + setupPersonalDrive over RA-TLS) and browses the
 * folder tree. The bell opens the share-requests screen, where raw
 * subs are decorated from the wallet's attribute referential.
 */

import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
    ActivityIndicator,
    Pressable,
    RefreshControl,
    ScrollView,
    StyleSheet,
    View as RNView,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { ensureDrive, type DriveNode } from '@/services/drive';
import { useDriveNotificationsStore } from '@/stores/drive-notifications';

function formatSize(bytes: number): string {
    if (!bytes) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

interface Crumb {
    id: string;
    name: string;
}

export default function DriveScreen() {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const [nodes, setNodes] = useState<DriveNode[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [path, setPath] = useState<Crumb[]>([]);
    const pendingCount = useDriveNotificationsStore(
        (s) => s.requests.filter((r) => !r.decision).length
    );

    const folder = path.length > 0 ? path[path.length - 1] : null;

    const load = useCallback(async (target: Crumb | null, asRefresh = false) => {
        if (asRefresh) setRefreshing(true);
        else setLoading(true);
        setError(null);
        try {
            const s = await ensureDrive();
            if (!s) {
                setError('Drive is not available on this deployment yet.');
                setNodes(null);
                return;
            }
            setNodes(
                target
                    ? await s.drive.listFolder(s.tenant.id, target.id)
                    : await s.drive.listRoot(s.tenant.id)
            );
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Could not open your drive.');
            setNodes(null);
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    }, []);

    useEffect(() => {
        void load(folder);
        // Hydrate the notifications store so the bell badge is live.
        void useDriveNotificationsStore.getState().hydrate();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [folder?.id]);

    const openFolder = (n: DriveNode) => {
        setPath((cur) => [...cur, { id: n.id, name: n.name }]);
    };
    const goBack = () => {
        setPath((cur) => cur.slice(0, -1));
    };

    return (
        <RNView style={styles.screen}>
            <RNView style={[styles.header, { paddingTop: insets.top + 16 }]}>
                <RNView style={styles.headerRow}>
                    <RNView style={styles.headerText}>
                        <Text style={styles.headerTitle}>Drive</Text>
                        <Text style={styles.headerSubtitle}>Your confidential files</Text>
                    </RNView>
                    <Pressable
                        style={styles.bell}
                        onPress={() => router.push('/drive-requests')}
                        accessibilityLabel="Share requests"
                    >
                        <Ionicons name="notifications-outline" size={22} color="#FFFFFF" />
                        {pendingCount > 0 && (
                            <RNView style={styles.badge}>
                                <Text style={styles.badgeText}>
                                    {pendingCount > 9 ? '9+' : String(pendingCount)}
                                </Text>
                            </RNView>
                        )}
                    </Pressable>
                </RNView>
            </RNView>

            {path.length > 0 && (
                <RNView style={styles.crumbBar}>
                    <Pressable style={styles.crumbBack} onPress={goBack}>
                        <Ionicons name="chevron-back" size={18} color={p.blue} />
                        <Text style={styles.crumbBackText}>
                            {path.length > 1 ? path[path.length - 2].name : 'Drive'}
                        </Text>
                    </Pressable>
                    <Text style={styles.crumbHere} numberOfLines={1}>
                        {folder?.name}
                    </Text>
                </RNView>
            )}

            <RNView style={styles.content}>
                {loading ? (
                    <ActivityIndicator style={styles.spinner} size="large" color={p.blue} />
                ) : error ? (
                    <RNView style={styles.emptyState}>
                        <Ionicons name="cloud-offline-outline" size={44} color={p.textMuted} />
                        <Text style={styles.emptyText}>{error}</Text>
                        <Pressable style={styles.retry} onPress={() => void load(folder)}>
                            <Text style={styles.retryText}>Try again</Text>
                        </Pressable>
                    </RNView>
                ) : nodes && nodes.length === 0 ? (
                    <RNView style={styles.emptyState}>
                        <Ionicons name="folder-open-outline" size={44} color={p.textMuted} />
                        <Text style={styles.emptyText}>
                            {folder ? 'This folder is empty.' : 'Your drive is empty.'}
                        </Text>
                    </RNView>
                ) : (
                    <ScrollView
                        contentContainerStyle={styles.list}
                        showsVerticalScrollIndicator={false}
                        refreshControl={
                            <RefreshControl
                                refreshing={refreshing}
                                onRefresh={() => void load(folder, true)}
                            />
                        }
                    >
                        {(nodes ?? []).map((n) => (
                            <Pressable
                                key={n.id}
                                style={styles.card}
                                disabled={n.kind !== 'folder'}
                                onPress={() => openFolder(n)}
                            >
                                <RNView
                                    style={[
                                        styles.icon,
                                        { backgroundColor: n.kind === 'folder' ? p.blue : '#8B5CF6' }
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
                                {n.kind === 'folder' && (
                                    <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                                )}
                            </Pressable>
                        ))}
                    </ScrollView>
                )}
            </RNView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    header: {
        backgroundColor: p.green,
        paddingHorizontal: 24,
        paddingBottom: 32,
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28
    },
    headerRow: { flexDirection: 'row', alignItems: 'flex-start' },
    headerText: { flex: 1 },
    headerTitle: { fontSize: 28, fontWeight: '700', color: '#FFFFFF', letterSpacing: -0.5, marginBottom: 4 },
    headerSubtitle: { fontSize: 15, color: 'rgba(255,255,255,0.8)' },
    bell: {
        width: 40,
        height: 40,
        borderRadius: 20,
        backgroundColor: 'rgba(255,255,255,0.15)',
        alignItems: 'center',
        justifyContent: 'center'
    },
    badge: {
        position: 'absolute',
        top: -2,
        right: -2,
        minWidth: 18,
        height: 18,
        borderRadius: 9,
        backgroundColor: '#DC2626',
        alignItems: 'center',
        justifyContent: 'center',
        paddingHorizontal: 4
    },
    badgeText: { fontSize: 10, fontWeight: '700', color: '#FFFFFF' },
    crumbBar: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingHorizontal: 16,
        paddingVertical: 10,
        gap: 10
    },
    crumbBack: { flexDirection: 'row', alignItems: 'center', gap: 2 },
    crumbBackText: { fontSize: 14, fontWeight: '600', color: p.blue },
    crumbHere: { flex: 1, fontSize: 14, color: p.textSecondary, textAlign: 'right' },
    content: { flex: 1 },
    spinner: { marginTop: 60 },
    list: { padding: 20, paddingTop: 16, paddingBottom: 96 },
    emptyState: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 40, gap: 12 },
    emptyText: { fontSize: 15, textAlign: 'center', color: p.textSecondary, lineHeight: 22 },
    retry: {
        marginTop: 8,
        backgroundColor: p.blue,
        borderRadius: 12,
        paddingHorizontal: 20,
        paddingVertical: 10
    },
    retryText: { color: '#FFFFFF', fontSize: 15, fontWeight: '600' },
    card: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: p.card,
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
    name: { fontSize: 16, fontWeight: '600', color: p.textPrimary },
    meta: { fontSize: 12, color: p.textSecondary, marginTop: 2 }
});
