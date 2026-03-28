import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { StyleSheet, ScrollView, Pressable, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

export default function HomeScreen() {
    const { apps } = useTrustedAppsStore();
    const insets = useSafeAreaInsets();
    const router = useRouter();

    return (
        <RNView style={styles.screen}>
            {/* Gradient header */}
            <RNView style={[styles.header, { paddingTop: insets.top + 16 }]}>
                <RNView style={styles.headerRow}>
                    <RNView />
                    <Pressable
                        onPress={() => router.push('/settings')}
                        style={styles.settingsButton}
                    >
                        <Ionicons name="settings-outline" size={22} color="rgba(255,255,255,0.9)" />
                    </Pressable>
                </RNView>
                <Text style={styles.headerTitle}>Privasys Wallet</Text>
                <Text style={styles.headerSubtitle}>
                    {apps.length === 0
                        ? 'No services connected yet'
                        : `${apps.length} connected service${apps.length !== 1 ? 's' : ''}`}
                </Text>
            </RNView>

            {/* Content */}
            <RNView style={styles.content}>
                {apps.length === 0 ? (
                    <RNView style={styles.emptyState}>
                        <RNView style={styles.emptyIconContainer}>
                            <Ionicons name="qr-code-outline" size={48} color="#00BCF2" />
                        </RNView>
                        <Text style={styles.emptyTitle}>Ready to connect</Text>
                        <Text style={styles.emptyText}>
                            Scan a QR code to verify and connect{`\n`}to your first enclave service.
                        </Text>
                    </RNView>
                ) : (
                    <ScrollView
                        style={styles.list}
                        contentContainerStyle={styles.listContent}
                        showsVerticalScrollIndicator={false}
                    >
                        <Text style={styles.sectionTitle}>CONNECTED SERVICES</Text>
                        {apps.map((app) => (
                            <RNView key={app.rpId} style={styles.serviceCard}>
                                <RNView
                                    style={[
                                        styles.serviceIcon,
                                        { backgroundColor: app.teeType === 'sgx' ? '#34E89E' : '#00BCF2' }
                                    ]}
                                >
                                    <Ionicons
                                        name={app.teeType === 'sgx' ? 'lock-closed' : 'shield-checkmark'}
                                        size={18}
                                        color="#FFFFFF"
                                    />
                                </RNView>
                                <RNView style={styles.serviceInfo}>
                                    <Text style={styles.serviceName}>{app.rpId}</Text>
                                    <Text style={styles.serviceMeta}>
                                        {app.teeType.toUpperCase()} · Verified{' '}
                                        {new Date(app.lastVerified * 1000).toLocaleDateString()}
                                    </Text>
                                </RNView>
                                <Ionicons name="chevron-forward" size={18} color="#C0C0C0" />
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
    headerRow: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 20
    },
    settingsButton: {
        width: 36,
        height: 36,
        borderRadius: 18,
        backgroundColor: 'rgba(255,255,255,0.2)',
        alignItems: 'center',
        justifyContent: 'center'
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
    listContent: { padding: 20, paddingTop: 24 },
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
    }
});
