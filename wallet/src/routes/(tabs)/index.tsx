import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { useEffect, useState } from 'react';
import { StyleSheet, ScrollView, Pressable, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import { useSessionsStore, type RelaySession } from '@/stores/sessions';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

/** Extract app name from rpId (e.g., "wasm-app-example" from "wasm-app-example.apps-test.privasys.org"). */
function appName(rpId: string): string {
    const dot = rpId.indexOf('.');
    return dot > 0 ? rpId.substring(0, dot) : rpId;
}

function formatRemaining(secondsLeft: number): string {
    if (secondsLeft <= 0) return 'expired';
    if (secondsLeft < 60) return `${secondsLeft}s left`;
    const m = Math.floor(secondsLeft / 60);
    if (m < 60) return `${m}m left`;
    const h = Math.floor(m / 60);
    return `${h}h ${m % 60}m left`;
}

export default function HomeScreen() {
    const { apps } = useTrustedAppsStore();
    const sessions = useSessionsStore((s) => s.sessions);
    const pruneExpired = useSessionsStore((s) => s.pruneExpired);
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));

    // Tick every second so the "remaining" label and pruning stay live.
    useEffect(() => {
        const id = setInterval(() => {
            setNow(Math.floor(Date.now() / 1000));
            pruneExpired();
        }, 1000);
        return () => clearInterval(id);
    }, [pruneExpired]);

    const liveSessions: RelaySession[] = sessions.filter((s) => s.expiresAt > now);

    return (
        <RNView style={styles.screen}>
            {/* Gradient header */}
            <RNView style={[styles.header, { paddingTop: insets.top + 16 }]}>
                <Text style={styles.headerTitle}>Privasys Wallet</Text>
                <Text style={styles.headerSubtitle}>
                    {apps.length === 0
                        ? 'No services connected yet'
                        : `${apps.length} connected service${apps.length !== 1 ? 's' : ''}`}
                </Text>
            </RNView>

            {/* Content */}
            <RNView style={styles.content}>
                {apps.length === 0 && liveSessions.length === 0 ? (
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
                    >
                        {liveSessions.length > 0 && (
                            <>
                                <Text style={styles.sectionTitle}>SESSIONS</Text>
                                {liveSessions.map((s) => (
                                    <RNView key={s.sessionId} style={styles.sessionCard}>
                                        <RNView style={styles.sessionDot} />
                                        <RNView style={styles.serviceInfo}>
                                            <Text style={styles.serviceName}>
                                                {s.appName ?? appName(s.rpId)}
                                            </Text>
                                            <Text style={styles.serviceMeta}>
                                                Relaying · {formatRemaining(s.expiresAt - now)}
                                            </Text>
                                        </RNView>
                                    </RNView>
                                ))}
                            </>
                        )}

                        {apps.length > 0 && (
                            <>
                                <Text
                                    style={[
                                        styles.sectionTitle,
                                        liveSessions.length > 0 && { marginTop: 24 }
                                    ]}
                                >
                                    CONNECTED SERVICES
                                </Text>
                                {apps.map((app) => (
                                    <Pressable
                                        key={app.rpId}
                                        style={styles.serviceCard}
                                        onPress={() =>
                                            router.push({
                                                pathname: '/service-detail',
                                                params: { rpId: app.rpId }
                                            })
                                        }
                                    >
                                        <RNView
                                            style={[
                                                styles.serviceIcon,
                                                {
                                                    backgroundColor:
                                                        app.teeType === 'sgx'
                                                            ? '#34E89E'
                                                            : app.teeType === 'tdx'
                                                                ? '#00BCF2'
                                                                : '#8B5CF6'
                                                }
                                            ]}
                                        >
                                            <Ionicons
                                                name={
                                                    app.teeType === 'sgx'
                                                        ? 'lock-closed'
                                                        : app.teeType === 'tdx'
                                                            ? 'shield-checkmark'
                                                            : 'key'
                                                }
                                                size={18}
                                                color="#FFFFFF"
                                            />
                                        </RNView>
                                        <RNView style={styles.serviceInfo}>
                                            <Text style={styles.serviceName}>{appName(app.rpId)}</Text>
                                            <Text style={styles.serviceMeta}>
                                                {app.teeType === 'none' ? 'Passkey' : app.teeType.toUpperCase()} · Connected{' '}
                                                {new Date(app.lastVerified * 1000).toLocaleDateString()}
                                            </Text>
                                        </RNView>
                                        <Ionicons name="chevron-forward" size={18} color="#C0C0C0" />
                                    </Pressable>
                                ))}
                            </>
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
    sessionCard: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 16,
        padding: 16,
        marginBottom: 10,
        borderWidth: 1,
        borderColor: 'rgba(52, 232, 158, 0.5)',
        shadowColor: '#0F172A',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.06,
        shadowRadius: 8,
        elevation: 2
    },
    sessionDot: {
        width: 10,
        height: 10,
        borderRadius: 5,
        backgroundColor: '#34E89E',
        marginRight: 14
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
    serviceName: {
        fontSize: 16,
        fontWeight: '600',
        color: '#0F172A',
        marginBottom: 2
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
