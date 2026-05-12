import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { StyleSheet, ScrollView, Pressable, TextInput, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import { useSessionsStore, type RelaySession } from '@/stores/sessions';
import { useTrustedAppsStore, type TrustedApp } from '@/stores/trusted-apps';

/** Threshold above which the search/filter box appears. */
const SEARCH_THRESHOLD = 10;

/** Extract app name from rpId (e.g., "wasm-app-example" from "wasm-app-example.apps-test.privasys.org"). */
function appName(rpId: string): string {
    const dot = rpId.indexOf('.');
    return dot > 0 ? rpId.substring(0, dot) : rpId;
}

function formatRemaining(msLeft: number): string {
    if (msLeft <= 0) return 'expired';
    const secondsLeft = Math.floor(msLeft / 1000);
    if (secondsLeft < 60) return `${secondsLeft}s left`;
    const m = Math.floor(secondsLeft / 60);
    if (m < 60) return `${m}m left`;
    const h = Math.floor(m / 60);
    return `${h}h ${m % 60}m left`;
}

/**
 * One row in the unified Active Sessions list. Rows are keyed by
 * rpId. A row may originate from a trusted app, a live relay session,
 * or both (sealed transport on a known app). See
 * `.operations/identity-platform/session-plan.md` §2.
 */
interface SessionRow {
    rpId: string;
    name: string;
    app?: TrustedApp;
    session?: RelaySession;
    /** Sort key: most-recently-active first. */
    lastActiveMs: number;
}

function buildRows(apps: TrustedApp[], sessions: RelaySession[], now: number): SessionRow[] {
    const live = sessions.filter((s) => s.expiresAt > now);
    const sessionByRpId = new Map<string, RelaySession>();
    for (const s of live) sessionByRpId.set(s.rpId, s);

    const rows: SessionRow[] = apps.map((app) => {
        const session = sessionByRpId.get(app.rpId);
        sessionByRpId.delete(app.rpId);
        return {
            rpId: app.rpId,
            name: appName(app.rpId),
            app,
            session,
            lastActiveMs: session ? session.startedAt : app.lastVerified * 1000
        };
    });
    // Orphan live sessions (no trusted-app row yet — rare, but possible).
    for (const session of sessionByRpId.values()) {
        rows.push({
            rpId: session.rpId,
            name: session.appName ?? appName(session.rpId),
            session,
            lastActiveMs: session.startedAt
        });
    }
    rows.sort((a, b) => b.lastActiveMs - a.lastActiveMs);
    return rows;
}

export default function HomeScreen() {
    const { apps } = useTrustedAppsStore();
    const sessions = useSessionsStore((s) => s.sessions);
    const pruneExpired = useSessionsStore((s) => s.pruneExpired);
    const insets = useSafeAreaInsets();
    const router = useRouter();
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

    const rows = useMemo(() => buildRows(apps, sessions, now), [apps, sessions, now]);
    const showSearch = rows.length > SEARCH_THRESHOLD;
    const filtered = useMemo(() => {
        const q = query.trim().toLowerCase();
        if (!q) return rows;
        return rows.filter(
            (r) => r.name.toLowerCase().includes(q) || r.rpId.toLowerCase().includes(q)
        );
    }, [rows, query]);

    return (
        <RNView style={styles.screen}>
            {/* Gradient header */}
            <RNView style={[styles.header, { paddingTop: insets.top + 16 }]}>
                <Text style={styles.headerTitle}>Privasys Wallet</Text>
                <Text style={styles.headerSubtitle}>
                    {rows.length === 0
                        ? 'No active sessions yet'
                        : `${rows.length} active session${rows.length !== 1 ? 's' : ''}`}
                </Text>
            </RNView>

            {/* Content */}
            <RNView style={styles.content}>
                {rows.length === 0 ? (
                    <RNView style={styles.emptyState}>
                        <RNView style={styles.emptyIconContainer}>
                            <Ionicons name="qr-code-outline" size={48} color="#00BCF2" />
                        </RNView>
                        <Text style={styles.emptyTitle}>Ready to connect</Text>
                        <Text style={styles.emptyText}>
                            Scan a QR code to connect{`\n`}to your first service.
                        </Text>
                    </RNView>
                ) : (
                    <ScrollView
                        style={styles.list}
                        contentContainerStyle={styles.listContent}
                        showsVerticalScrollIndicator={false}
                        keyboardShouldPersistTaps="handled"
                    >
                        {showSearch && (
                            <RNView style={styles.searchBox}>
                                <Ionicons
                                    name="search"
                                    size={16}
                                    color="#64748B"
                                    style={styles.searchIcon}
                                />
                                <TextInput
                                    style={styles.searchInput}
                                    placeholder="Search sessions"
                                    placeholderTextColor="#94A3B8"
                                    value={query}
                                    onChangeText={setQuery}
                                    autoCapitalize="none"
                                    autoCorrect={false}
                                    returnKeyType="search"
                                    accessibilityLabel="Search sessions"
                                />
                                {query.length > 0 && (
                                    <Pressable
                                        onPress={() => setQuery('')}
                                        accessibilityLabel="Clear search"
                                        hitSlop={8}
                                    >
                                        <Ionicons
                                            name="close-circle"
                                            size={18}
                                            color="#94A3B8"
                                        />
                                    </Pressable>
                                )}
                            </RNView>
                        )}

                        <Text style={styles.sectionTitle}>ACTIVE SESSIONS</Text>

                        {filtered.length === 0 ? (
                            <Text style={styles.noResults}>
                                No sessions match &ldquo;{query}&rdquo;.
                            </Text>
                        ) : (
                            filtered.map((row) => {
                                const sealed = !!row.session;
                                const teeType = row.app?.teeType ?? 'none';
                                const iconBg =
                                    teeType === 'sgx'
                                        ? '#34E89E'
                                        : teeType === 'tdx'
                                            ? '#00BCF2'
                                            : '#8B5CF6';
                                const iconName: keyof typeof Ionicons.glyphMap =
                                    teeType === 'sgx'
                                        ? 'lock-closed'
                                        : teeType === 'tdx'
                                            ? 'shield-checkmark'
                                            : 'key';
                                const onPress = row.app
                                    ? () =>
                                        router.push({
                                            pathname: '/service-detail',
                                            params: { rpId: row.rpId }
                                        })
                                    : undefined;
                                return (
                                    <Pressable
                                        key={row.rpId}
                                        style={[
                                            styles.serviceCard,
                                            sealed && styles.serviceCardSealed
                                        ]}
                                        onPress={onPress}
                                        disabled={!onPress}
                                    >
                                        <RNView
                                            style={[styles.serviceIcon, { backgroundColor: iconBg }]}
                                        >
                                            <Ionicons name={iconName} size={18} color="#FFFFFF" />
                                        </RNView>
                                        <RNView style={styles.serviceInfo}>
                                            <RNView style={styles.serviceNameRow}>
                                                <Text style={styles.serviceName}>{row.name}</Text>
                                                {sealed && (
                                                    <RNView style={styles.sealedBadge}>
                                                        <RNView style={styles.sealedDot} />
                                                        <Text style={styles.sealedText}>Sealed</Text>
                                                    </RNView>
                                                )}
                                            </RNView>
                                            <Text style={styles.serviceMeta}>
                                                {sealed && row.session
                                                    ? `Relaying · ${formatRemaining(row.session.expiresAt - now)}`
                                                    : row.app
                                                        ? `${teeType === 'none' ? 'Passkey' : teeType.toUpperCase()} · Connected ${new Date(row.app.lastVerified * 1000).toLocaleDateString()}`
                                                        : 'Active session'}
                                            </Text>
                                        </RNView>
                                        {onPress && (
                                            <Ionicons
                                                name="chevron-forward"
                                                size={18}
                                                color="#C0C0C0"
                                            />
                                        )}
                                    </Pressable>
                                );
                            })
                        )}
                    </ScrollView>
                )}
            </RNView>

            {/* Floating scan button — replaces the standalone Scan tab. */}
            <Pressable
                style={styles.scanFab}
                onPress={() => router.push('/scan')}
                accessibilityLabel="Scan QR code"
            >
                <Ionicons name="qr-code-outline" size={26} color="#FFFFFF" />
            </Pressable>
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
    headerTitle: {
        fontSize: 28,
        fontWeight: '700',
        color: '#FFFFFF',
        letterSpacing: -0.5,
        marginBottom: 4
    },
    headerSubtitle: {
        fontSize: 15,
        color: 'rgba(255,255,255,0.8)'
    },
    content: { flex: 1 },
    emptyState: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        paddingHorizontal: 40,
        paddingBottom: 80
    },
    emptyIconContainer: {
        width: 88,
        height: 88,
        borderRadius: 44,
        backgroundColor: 'rgba(0, 188, 242, 0.08)',
        alignItems: 'center',
        justifyContent: 'center',
        marginBottom: 24
    },
    emptyTitle: {
        fontSize: 20,
        fontWeight: '600',
        color: '#0F172A',
        marginBottom: 8
    },
    emptyText: {
        fontSize: 15,
        textAlign: 'center',
        color: '#64748B',
        lineHeight: 22
    },
    list: { flex: 1 },
    listContent: { padding: 20, paddingTop: 24, paddingBottom: 96 },
    sectionTitle: {
        fontSize: 12,
        fontWeight: '700',
        color: '#64748B',
        letterSpacing: 1,
        marginBottom: 12
    },
    serviceCard: {
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
    serviceCardSealed: {
        borderWidth: 1,
        borderColor: 'rgba(52, 232, 158, 0.5)'
    },
    searchBox: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        paddingHorizontal: 12,
        height: 40,
        marginBottom: 16,
        shadowColor: '#0F172A',
        shadowOffset: { width: 0, height: 1 },
        shadowOpacity: 0.04,
        shadowRadius: 4,
        elevation: 1
    },
    searchIcon: { marginRight: 8 },
    searchInput: {
        flex: 1,
        fontSize: 15,
        color: '#0F172A',
        paddingVertical: 0
    },
    noResults: {
        fontSize: 14,
        color: '#64748B',
        textAlign: 'center',
        paddingVertical: 24
    },
    sealedBadge: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: 'rgba(52, 232, 158, 0.12)',
        borderRadius: 10,
        paddingHorizontal: 8,
        paddingVertical: 2,
        marginLeft: 8
    },
    sealedDot: {
        width: 6,
        height: 6,
        borderRadius: 3,
        backgroundColor: '#34E89E',
        marginRight: 4
    },
    sealedText: {
        fontSize: 11,
        fontWeight: '600',
        color: '#0E7C4A'
    },
    serviceIcon: {
        width: 40,
        height: 40,
        borderRadius: 12,
        alignItems: 'center',
        justifyContent: 'center',
        marginRight: 14
    },
    serviceInfo: { flex: 1 },
    serviceNameRow: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 2
    },
    serviceName: {
        fontSize: 16,
        fontWeight: '600',
        color: '#0F172A'
    },
    serviceMeta: {
        fontSize: 12,
        color: '#64748B'
    },
    scanFab: {
        position: 'absolute',
        right: 24,
        bottom: 24,
        width: 60,
        height: 60,
        borderRadius: 30,
        backgroundColor: '#00BCF2',
        alignItems: 'center',
        justifyContent: 'center',
        shadowColor: '#00BCF2',
        shadowOffset: { width: 0, height: 6 },
        shadowOpacity: 0.4,
        shadowRadius: 12,
        elevation: 8
    }
});
