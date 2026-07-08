import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { StyleSheet, ScrollView, Pressable, TextInput, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import {
    KIND_LABELS,
    serviceHosts,
    type SessionTrace,
    useServiceSessionsStore
} from '@/stores/service-sessions';
import { useSessionsStore, type RelaySession } from '@/stores/sessions';
import { useTrustedAppsStore, type TrustedApp } from '@/stores/trusted-apps';
import { useVaultApprovalsStore } from '@/stores/vaultApprovals';

/** Threshold above which the search/filter box appears. */
const SEARCH_THRESHOLD = 10;

/** Extract app name from rpId (e.g., "wasm-app-example" from "wasm-app-example.apps-test.privasys.org"). */
function appName(rpId: string): string {
    const dot = rpId.indexOf('.');
    return dot > 0 ? rpId.substring(0, dot) : rpId;
}

/**
 * One card in the sessions list — one per APP the user authenticated to
 * (serviceKey = OIDC client id / enclave host), never per shared rpId, so
 * "Privasys Chat" and "Developer Platform" stay separate cards even though
 * both ride the privasys.id RP. A card aggregates that app's session traces,
 * plus its live sealed relay session and legacy trusted-app row when present.
 */
interface SessionRow {
    key: string;
    name: string;
    /** Latest trace for this app (drives the type label + subtitle). */
    trace?: SessionTrace;
    /** Legacy trusted-app row (pre-trace installs) backing this card. */
    app?: TrustedApp;
    session?: RelaySession;
    teeType: TrustedApp['teeType'];
    /** Sort key: most-recently-active first. */
    lastActiveMs: number;
}

function buildRows(
    traces: SessionTrace[],
    apps: TrustedApp[],
    sessions: RelaySession[],
    now: number
): SessionRow[] {
    const live = sessions.filter((s) => s.expiresAt > now);
    const sessionByHost = new Map<string, RelaySession>();
    for (const s of live) sessionByHost.set(s.rpId, s);

    // Group traces per app.
    const byService = new Map<string, SessionTrace[]>();
    for (const t of traces) {
        const list = byService.get(t.serviceKey);
        if (list) list.push(t);
        else byService.set(t.serviceKey, [t]);
    }

    const coveredHosts = new Set<string>();
    const coveredSessions = new Set<string>();
    const rows: SessionRow[] = [];

    for (const [key, list] of byService) {
        const latest = list[0]; // store is newest-first
        const hosts = serviceHosts(list);
        for (const h of hosts) coveredHosts.add(h);
        // A live sealed session belongs to this card when it is keyed by any
        // host this app's ceremonies touched.
        let session: RelaySession | undefined;
        for (const h of hosts) {
            const s = sessionByHost.get(h);
            if (s) {
                session = s;
                coveredSessions.add(s.sessionId);
                break;
            }
        }
        const att = list.find((t) => t.attestations?.length)?.attestations?.[0];
        rows.push({
            key,
            name: latest.displayName ?? appName(key),
            trace: latest,
            app: apps.find((a) => hosts.has(a.rpId)),
            session,
            teeType: att?.teeType ?? 'none',
            lastActiveMs: session ? Math.max(session.startedAt, latest.startedAt) : latest.startedAt
        });
    }

    // Legacy trusted-app rows not covered by any trace yet (installs that
    // predate the per-app trail) keep their card so nothing disappears.
    for (const app of apps) {
        if (coveredHosts.has(app.rpId)) continue;
        const session = sessionByHost.get(app.rpId);
        if (session) coveredSessions.add(session.sessionId);
        rows.push({
            key: app.rpId,
            name: app.appName ?? appName(app.rpId),
            app,
            session,
            teeType: app.teeType,
            lastActiveMs: session ? session.startedAt : app.lastVerified * 1000
        });
    }

    // Orphan live sessions (no trace, no trusted-app row — rare).
    for (const session of live) {
        if (coveredSessions.has(session.sessionId)) continue;
        rows.push({
            key: session.rpId,
            name: session.appName ?? appName(session.rpId),
            session,
            teeType: 'none',
            lastActiveMs: session.startedAt
        });
    }

    rows.sort((a, b) => b.lastActiveMs - a.lastActiveMs);
    return rows;
}

/** Compact "when" for the card subtitle. */
function relativeWhen(ms: number, now: number): string {
    const diff = now - ms;
    if (diff < 60_000) return 'just now';
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return new Date(ms).toLocaleDateString();
}

export default function HomeScreen() {
    const { apps } = useTrustedAppsStore();
    const traces = useServiceSessionsStore((s) => s.traces);
    const sessions = useSessionsStore((s) => s.sessions);
    const pruneExpired = useSessionsStore((s) => s.pruneExpired);
    const pendingApprovals = useVaultApprovalsStore((s) => s.pending);
    const refreshApprovals = useVaultApprovalsStore((s) => s.refresh);
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

    // Keep the pending-approvals banner live: fetch on mount and every 20s so
    // the count reflects approvals that arrived (tray sweep) or expired.
    useEffect(() => {
        void refreshApprovals();
        const id = setInterval(() => void refreshApprovals(), 20000);
        return () => clearInterval(id);
    }, [refreshApprovals]);

    const rows = useMemo(
        () => buildRows(traces, apps, sessions, now),
        [traces, apps, sessions, now]
    );
    const showSearch = rows.length > SEARCH_THRESHOLD;
    const filtered = useMemo(() => {
        const q = query.trim().toLowerCase();
        if (!q) return rows;
        return rows.filter(
            (r) => r.name.toLowerCase().includes(q) || r.key.toLowerCase().includes(q)
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
                {pendingApprovals.length > 0 && (
                    <Pressable
                        style={styles.approvalsBanner}
                        onPress={() => router.push('/vault-approvals')}
                        accessibilityLabel={`${pendingApprovals.length} pending vault approval${pendingApprovals.length !== 1 ? 's' : ''}`}
                    >
                        <RNView style={styles.approvalsIcon}>
                            <Ionicons name="key" size={18} color="#0F766E" />
                        </RNView>
                        <RNView style={styles.approvalsInfo}>
                            <Text style={styles.approvalsTitle}>
                                {pendingApprovals.length} pending approval
                                {pendingApprovals.length !== 1 ? 's' : ''}
                            </Text>
                            <Text style={styles.approvalsMeta}>Tap to review and approve with your passkey</Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color="#0F766E" />
                    </Pressable>
                )}
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
                                // Type/tech differences stay SUBTLE: same card
                                // anatomy for every session type; only the icon
                                // tint and the one-line meta text vary, plus a
                                // small live dot when a sealed session is up.
                                const teeType = row.teeType;
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
                                const kindLabel = row.trace
                                    ? KIND_LABELS[row.trace.kind]
                                    : teeType === 'none'
                                        ? 'Passkey'
                                        : 'Enclave';
                                const meta = `${kindLabel} · ${relativeWhen(row.lastActiveMs, now)}`;
                                const onPress =
                                    row.trace || row.app
                                        ? () =>
                                            router.push({
                                                pathname: '/service-detail',
                                                params: { serviceKey: row.key }
                                            })
                                        : undefined;
                                return (
                                    <Pressable
                                        key={row.key}
                                        style={styles.serviceCard}
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
                                                {row.session && <RNView style={styles.liveDot} />}
                                            </RNView>
                                            <Text style={styles.serviceMeta}>{meta}</Text>
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
    approvalsBanner: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12,
        marginHorizontal: 20,
        marginTop: 16,
        backgroundColor: 'rgba(52, 232, 158, 0.12)',
        borderRadius: 14,
        paddingHorizontal: 14,
        paddingVertical: 14
    },
    approvalsIcon: {
        width: 36,
        height: 36,
        borderRadius: 18,
        backgroundColor: 'rgba(52, 232, 158, 0.22)',
        alignItems: 'center',
        justifyContent: 'center'
    },
    approvalsInfo: { flex: 1 },
    approvalsTitle: { fontSize: 15, fontWeight: '700', color: '#0F172A' },
    approvalsMeta: { fontSize: 12, color: '#0F766E', marginTop: 2 },
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
    liveDot: {
        width: 7,
        height: 7,
        borderRadius: 4,
        backgroundColor: '#34E89E',
        marginLeft: 8
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
