// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Server Sessions screen — lists and revokes the current user's
 * sessions as recorded server-side by the IdP `internal/sessions`
 * package. Each row is one `(user, app, device)` JWT-revocation handle.
 *
 * Auth uses the wallet session token from the user's privasys.id
 * meta-account. When the token is missing or expired, the screen shows
 * a sign-in prompt rather than a confusing 401 list.
 */

import { Ionicons } from '@expo/vector-icons';
import { useRouter, Stack } from 'expo-router';
import { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, Alert, Pressable, RefreshControl, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import { listMySessions, revokeSession, type IdpSession } from '@/services/sessions-api';
import { useAuthStore } from '@/stores/auth';

function shortSid(sid: string): string {
    return sid.length > 12 ? `${sid.slice(0, 6)}\u2026${sid.slice(-6)}` : sid;
}

function relative(unixSeconds: number): string {
    const delta = Math.max(0, Math.floor(Date.now() / 1000 - unixSeconds));
    if (delta < 60) return 'just now';
    if (delta < 3600) return `${Math.floor(delta / 60)} min ago`;
    if (delta < 86400) return `${Math.floor(delta / 3600)} h ago`;
    return `${Math.floor(delta / 86400)} d ago`;
}

export default function ServerSessionsScreen() {
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const privasysId = useAuthStore((s) => s.privasysId);
    const sessionToken = privasysId?.sessionToken ?? '';
    const sessionExpiresAt = privasysId?.sessionExpiresAt ?? 0;
    const haveAuth = sessionToken !== '' && sessionExpiresAt > Date.now();

    const [sessions, setSessions] = useState<IdpSession[] | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [revoking, setRevoking] = useState<string | null>(null);

    const refresh = useCallback(async () => {
        if (!haveAuth) return;
        setLoading(true);
        setError(null);
        try {
            const list = await listMySessions(sessionToken);
            setSessions(list);
        } catch (e) {
            setError((e as Error).message);
        } finally {
            setLoading(false);
        }
    }, [haveAuth, sessionToken]);

    useEffect(() => {
        if (haveAuth) refresh();
    }, [haveAuth, refresh]);

    const handleRevoke = (sess: IdpSession) => {
        Alert.alert(
            'Revoke Session',
            `Revoke the session for ${sess.client_id}? Tokens issued for this session will stop working immediately.`,
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Revoke',
                    style: 'destructive',
                    onPress: async () => {
                        setRevoking(sess.sid);
                        try {
                            await revokeSession(sessionToken, sess.sid);
                            setSessions((cur) => (cur ?? []).filter((s) => s.sid !== sess.sid));
                        } catch (e) {
                            Alert.alert('Revoke failed', (e as Error).message);
                        } finally {
                            setRevoking(null);
                        }
                    },
                },
            ]
        );
    };

    return (
        <>
            <Stack.Screen options={{ headerShown: false }} />
            <RNView style={styles.screen}>
                <RNView style={[styles.header, { paddingTop: insets.top + 12 }]}>
                    <Pressable onPress={() => router.back()} style={styles.backArrow}>
                        <Ionicons name="chevron-back" size={24} color="#FFFFFF" />
                    </Pressable>
                    <Text style={styles.headerTitle}>Server Sessions</Text>
                    <RNView style={{ width: 36 }} />
                </RNView>

                <ScrollView
                    contentContainerStyle={styles.content}
                    refreshControl={<RefreshControl refreshing={loading} onRefresh={refresh} />}
                >
                    <Text style={styles.intro}>
                        These are the active sessions the privasys.id IdP has recorded for your
                        account. Revoking a session invalidates every JWT issued under it
                        (including refresh tokens), so the corresponding app will require a fresh
                        sign-in.
                    </Text>

                    {!haveAuth && (
                        <RNView style={styles.notice}>
                            <Ionicons name="information-circle-outline" size={18} color="#0F172A" />
                            <Text style={styles.noticeText}>
                                Sign in to your privasys.id account from Settings to manage server
                                sessions.
                            </Text>
                        </RNView>
                    )}

                    {error && (
                        <RNView style={[styles.notice, styles.noticeError]}>
                            <Ionicons name="alert-circle-outline" size={18} color="#B91C1C" />
                            <Text style={[styles.noticeText, { color: '#B91C1C' }]}>{error}</Text>
                        </RNView>
                    )}

                    {haveAuth && loading && sessions === null && (
                        <RNView style={styles.loading}>
                            <ActivityIndicator color="#34E89E" />
                        </RNView>
                    )}

                    {haveAuth && sessions !== null && sessions.length === 0 && !loading && (
                        <Text style={styles.empty}>No active server sessions.</Text>
                    )}

                    {haveAuth && sessions !== null && sessions.map((sess) => (
                        <RNView key={sess.sid} style={styles.row}>
                            <RNView style={styles.rowMain}>
                                <Text style={styles.client}>{sess.client_id}</Text>
                                <Text style={styles.sid} selectable>{shortSid(sess.sid)}</Text>
                                <Text style={styles.meta}>
                                    Last seen {relative(sess.last_seen_at)} \u00b7 expires{' '}
                                    {new Date(sess.expires_at * 1000).toLocaleDateString()}
                                </Text>
                            </RNView>
                            <Pressable
                                onPress={() => handleRevoke(sess)}
                                disabled={revoking === sess.sid}
                                style={[styles.revokeBtn, revoking === sess.sid && styles.revokeBtnBusy]}
                            >
                                {revoking === sess.sid ? (
                                    <ActivityIndicator color="#FF3B30" size="small" />
                                ) : (
                                    <Ionicons name="trash-outline" size={18} color="#FF3B30" />
                                )}
                            </Pressable>
                        </RNView>
                    ))}
                </ScrollView>
            </RNView>
        </>
    );
}

const styles = StyleSheet.create({
    screen: { flex: 1, backgroundColor: '#F8FAFB' },
    header: {
        backgroundColor: '#34E89E',
        paddingHorizontal: 16,
        paddingBottom: 16,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28,
    },
    backArrow: {
        width: 36,
        height: 36,
        borderRadius: 18,
        backgroundColor: 'rgba(255,255,255,0.2)',
        alignItems: 'center',
        justifyContent: 'center',
    },
    headerTitle: { fontSize: 17, fontWeight: '600', color: '#FFFFFF' },
    content: { padding: 20, gap: 12 },
    intro: { fontSize: 13, color: '#64748B', marginBottom: 8 },
    notice: {
        flexDirection: 'row',
        gap: 8,
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 12,
        alignItems: 'flex-start',
    },
    noticeError: { backgroundColor: '#FEF2F2' },
    noticeText: { fontSize: 13, color: '#0F172A', flex: 1 },
    loading: { paddingVertical: 32, alignItems: 'center' },
    empty: { fontSize: 14, color: '#94A3B8', textAlign: 'center', paddingVertical: 32 },
    row: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 14,
        gap: 12,
    },
    rowMain: { flex: 1, gap: 2 },
    client: { fontSize: 14, fontWeight: '600', color: '#0F172A' },
    sid: { fontSize: 11, color: '#94A3B8', fontFamily: 'Inter' },
    meta: { fontSize: 12, color: '#64748B', marginTop: 2 },
    revokeBtn: {
        width: 40,
        height: 40,
        borderRadius: 12,
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#FEF2F2',
    },
    revokeBtnBusy: { opacity: 0.5 },
});
