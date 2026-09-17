// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Every app the holder has signed in to, in full.
 *
 * This was the wallet's home tab until the Access tab replaced it. A list of
 * sessions is something you consult, not something you land on, and at 33 rows
 * it filled the screen and pushed everything else off it. Access now shows the
 * most recent few and a count; this is the rest, with the search box that only
 * ever made sense here.
 */

import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import {
    Alert,
    Pressable,
    ScrollView,
    StyleSheet,
    TextInput,
    View as RNView,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { KIND_LABEL_KEYS, useServiceSessionsStore } from '@/stores/service-sessions';
import { useSessionsStore, type RelaySession } from '@/stores/sessions';
import { useTrustedAppsStore } from '@/stores/trusted-apps';
import { appName, buildSessionRows, relativeWhen } from '@/utils/session-rows';

/** Threshold above which the search box appears. */
const SEARCH_THRESHOLD = 10;

export default function SessionsScreen() {
    const { apps } = useTrustedAppsStore();
    const traces = useServiceSessionsStore((s) => s.traces);
    const sessions = useSessionsStore((s) => s.sessions);
    const pruneExpired = useSessionsStore((s) => s.pruneExpired);
    const removeRelaySession = useSessionsStore((s) => s.remove);
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { t } = useTranslation();
    const [now, setNow] = useState(() => Date.now());
    const [query, setQuery] = useState('');

    // Tick every second so the "remaining" label and pruning stay live.
    useEffect(() => {
        const id = setInterval(() => {
            setNow(Date.now());
            pruneExpired();
        }, 1000);
        return () => clearInterval(id);
    }, [pruneExpired]);

    // End an orphaned live sealed session, one with no trace or credential
    // behind it and so no service-detail page. Without this the row can only
    // clear itself when its TTL expires, which the holder cannot hurry.
    const endOrphanSession = (session: RelaySession) => {
        Alert.alert(
            t('home.endSessionTitle'),
            t('home.endSessionBody', { app: session.appName ?? appName(session.rpId) }),
            [
                { text: t('common.cancel'), style: 'cancel' },
                {
                    text: t('home.endSessionConfirm'),
                    style: 'destructive',
                    onPress: () => removeRelaySession(session.sessionId),
                },
            ],
        );
    };

    const rows = useMemo(
        () => buildSessionRows(traces, apps, sessions, now),
        [traces, apps, sessions, now],
    );
    const showSearch = rows.length > SEARCH_THRESHOLD;
    const filtered = useMemo(() => {
        const q = query.trim().toLowerCase();
        if (!q) return rows;
        return rows.filter(
            (r) => r.name.toLowerCase().includes(q) || r.key.toLowerCase().includes(q),
        );
    }, [rows, query]);

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('sessions.title')} />
            <ScrollView
                style={styles.list}
                contentContainerStyle={[styles.listContent, { paddingBottom: insets.bottom + 32 }]}
                showsVerticalScrollIndicator={false}
                keyboardShouldPersistTaps="handled"
            >
                {rows.length === 0 ? (
                    <Text style={styles.empty}>{t('sessions.empty')}</Text>
                ) : (
                    <>
                        {showSearch && (
                            <RNView style={styles.searchBox}>
                                <Ionicons
                                    name="search"
                                    size={16}
                                    color={p.textSecondary}
                                    style={styles.searchIcon}
                                />
                                <TextInput
                                    style={styles.searchInput}
                                    placeholder={t('home.searchPlaceholder')}
                                    placeholderTextColor={p.textMuted}
                                    value={query}
                                    onChangeText={setQuery}
                                    autoCapitalize="none"
                                    autoCorrect={false}
                                    returnKeyType="search"
                                    accessibilityLabel={t('home.searchPlaceholder')}
                                />
                                {query.length > 0 && (
                                    <Pressable
                                        onPress={() => setQuery('')}
                                        accessibilityLabel={t('home.clearSearch')}
                                        hitSlop={8}
                                    >
                                        <Ionicons name="close-circle" size={18} color={p.textMuted} />
                                    </Pressable>
                                )}
                            </RNView>
                        )}

                        {filtered.length === 0 ? (
                            <Text style={styles.noResults}>{t('home.noResults', { query })}</Text>
                        ) : (
                            filtered.map((row) => {
                                // Type and technology differences stay SUBTLE: the
                                // same card anatomy for every session type, with
                                // only the icon tint and the one-line meta varying,
                                // plus a small live dot when a sealed session is up.
                                const teeType = row.teeType;
                                const iconBg =
                                    teeType === 'sgx' ? p.green : teeType === 'tdx' ? p.blue : '#8B5CF6';
                                const iconName: keyof typeof Ionicons.glyphMap =
                                    teeType === 'sgx'
                                        ? 'lock-closed'
                                        : teeType === 'tdx'
                                            ? 'shield-checkmark'
                                            : 'key';
                                const kindLabel = row.trace
                                    ? t(KIND_LABEL_KEYS[row.trace.kind])
                                    : teeType === 'none'
                                        ? t('identityKind.passkey')
                                        : t('sessionKind.enclave');
                                const meta = t('home.cardMeta', {
                                    kind: kindLabel,
                                    when: relativeWhen(row.lastActiveMs, now, t),
                                });
                                const onPress =
                                    row.trace || row.app
                                        ? () =>
                                            router.push({
                                                pathname: '/service-detail',
                                                params: { serviceKey: row.key },
                                            })
                                        : row.session
                                            ? () => endOrphanSession(row.session!)
                                            : undefined;
                                return (
                                    <Pressable
                                        key={row.key}
                                        style={styles.serviceCard}
                                        onPress={onPress}
                                        disabled={!onPress}
                                    >
                                        <RNView style={[styles.serviceIcon, { backgroundColor: iconBg }]}>
                                            <Ionicons name={iconName} size={18} color="#FFFFFF" />
                                            {/* Live-session badge on the icon corner, a fixed
                                                spot that stays put no matter how many lines
                                                the service name wraps to. */}
                                            {row.session && <RNView style={styles.liveDot} />}
                                        </RNView>
                                        <RNView style={styles.serviceInfo}>
                                            <Text style={styles.serviceName}>{row.name}</Text>
                                            <Text style={styles.serviceMeta}>{meta}</Text>
                                        </RNView>
                                        {onPress && (
                                            <Ionicons
                                                name={
                                                    row.trace || row.app
                                                        ? 'chevron-forward'
                                                        : 'close-circle-outline'
                                                }
                                                size={18}
                                                color={p.textMuted}
                                            />
                                        )}
                                    </Pressable>
                                );
                            })
                        )}
                    </>
                )}
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    list: { flex: 1 },
    listContent: { padding: 20 },
    empty: { fontSize: 15, color: p.textSecondary, textAlign: 'center', paddingVertical: 40 },
    searchBox: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: p.card,
        borderRadius: 12,
        paddingHorizontal: 12,
        height: 40,
        marginBottom: 16,
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 1 },
        shadowOpacity: 0.04,
        shadowRadius: 4,
        elevation: 1,
    },
    searchIcon: { marginRight: 8 },
    searchInput: { flex: 1, fontSize: 15, color: p.textPrimary, paddingVertical: 0 },
    noResults: {
        fontSize: 14,
        color: p.textSecondary,
        textAlign: 'center',
        paddingVertical: 24,
    },
    serviceCard: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: p.card,
        borderRadius: 16,
        padding: 16,
        marginBottom: 10,
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.06,
        shadowRadius: 8,
        elevation: 2,
    },
    serviceIcon: {
        width: 40,
        height: 40,
        borderRadius: 12,
        alignItems: 'center',
        justifyContent: 'center',
        marginRight: 14,
    },
    serviceInfo: { flex: 1 },
    serviceName: { marginBottom: 2, fontSize: 16, fontWeight: '600', color: p.textPrimary },
    liveDot: {
        position: 'absolute',
        top: -3,
        right: -3,
        width: 14,
        height: 14,
        borderRadius: 7,
        backgroundColor: p.green,
        // Ring in the card colour so the dot reads as a floating badge over
        // the (green, blue or purple) icon.
        borderWidth: 3,
        borderColor: p.card,
    },
    serviceMeta: { fontSize: 12, color: p.textSecondary },
});
