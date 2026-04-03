// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { Ionicons } from '@expo/vector-icons';
import { useRouter, useLocalSearchParams, Stack } from 'expo-router';
import { useState } from 'react';
import { StyleSheet, Pressable, Alert, ScrollView, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import { useAuthStore } from '@/stores/auth';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

export default function ServiceDetailScreen() {
    const router = useRouter();
    const { rpId } = useLocalSearchParams<{ rpId: string }>();
    const insets = useSafeAreaInsets();

    const { apps, remove: removeTrustedApp } = useTrustedAppsStore();
    const { removeCredential, credentials } = useAuthStore();

    const app = apps.find((a) => a.rpId === rpId);
    const credential = credentials.find((c) => c.rpId === rpId);
    const [removing, setRemoving] = useState(false);

    const handleRemove = () => {
        Alert.alert(
            'Remove Service',
            `Disconnect from ${rpId}? You will need to scan the QR code again to reconnect.`,
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Remove',
                    style: 'destructive',
                    onPress: async () => {
                        setRemoving(true);
                        if (credential) removeCredential(credential.credentialId);
                        if (rpId) removeTrustedApp(rpId);
                        router.replace('/(tabs)');
                    }
                }
            ]
        );
    };

    if (!app) {
        return (
            <>
                <Stack.Screen options={{ headerShown: false }} />
                <RNView style={[styles.screen, { paddingTop: insets.top }]}>
                    <Text style={styles.notFound}>Service not found</Text>
                    <Pressable style={styles.backButton} onPress={() => router.back()}>
                        <Text style={styles.backButtonText}>Go back</Text>
                    </Pressable>
                </RNView>
            </>
        );
    }

    return (
        <>
            <Stack.Screen options={{ headerShown: false }} />
            <RNView style={styles.screen}>
                {/* Header */}
                <RNView style={[styles.header, { paddingTop: insets.top + 12 }]}>
                    <Pressable onPress={() => router.back()} style={styles.backArrow}>
                        <Ionicons name="chevron-back" size={24} color="#FFFFFF" />
                    </Pressable>
                    <Text style={styles.headerTitle}>Service Details</Text>
                    <RNView style={{ width: 36 }} />
                </RNView>

                <ScrollView contentContainerStyle={styles.content}>
                    {/* Service icon + name */}
                    <RNView style={styles.serviceHeader}>
                        <RNView
                            style={[
                                styles.serviceIcon,
                                { backgroundColor: app.teeType === 'sgx' ? '#34E89E' : '#00BCF2' }
                            ]}
                        >
                            <Ionicons
                                name={app.teeType === 'sgx' ? 'lock-closed' : 'shield-checkmark'}
                                size={28}
                                color="#FFFFFF"
                            />
                        </RNView>
                        <Text style={styles.serviceName}>{app.rpId}</Text>
                        <Text style={styles.serviceMeta}>
                            {app.teeType.toUpperCase()} · Verified{' '}
                            {new Date(app.lastVerified * 1000).toLocaleDateString()}
                        </Text>
                    </RNView>

                    {/* Attestation details */}
                    <RNView style={styles.card}>
                        <Text style={styles.cardTitle}>Attestation</Text>
                        <DetailRow label="TEE Type" value={app.teeType.toUpperCase()} />
                        {app.mrenclave && <DetailRow label="MRENCLAVE" value={app.mrenclave} mono />}
                        {app.mrtd && <DetailRow label="MRTD" value={app.mrtd} mono />}
                        {app.codeHash && <DetailRow label="Code Hash" value={app.codeHash} mono />}
                        {app.configRoot && <DetailRow label="Config Root" value={app.configRoot} mono />}
                        <DetailRow label="Origin" value={app.origin} />
                        {credential && (
                            <DetailRow
                                label="Registered"
                                value={new Date(credential.registeredAt * 1000).toLocaleDateString()}
                            />
                        )}
                    </RNView>

                    {/* Remove */}
                    <Pressable
                        style={[styles.removeButton, removing && styles.removeButtonDisabled]}
                        onPress={handleRemove}
                        disabled={removing}
                    >
                        <Ionicons name="trash-outline" size={18} color="#FF3B30" />
                        <Text style={styles.removeButtonText}>Remove Service</Text>
                    </Pressable>
                </ScrollView>
            </RNView>
        </>
    );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
    return (
        <RNView style={styles.detailRow}>
            <Text style={styles.detailLabel}>{label}</Text>
            <Text style={[styles.detailValue, mono && styles.mono]} selectable numberOfLines={2}>
                {value}
            </Text>
        </RNView>
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
        borderBottomRightRadius: 28
    },
    backArrow: {
        width: 36,
        height: 36,
        borderRadius: 18,
        backgroundColor: 'rgba(255,255,255,0.2)',
        alignItems: 'center',
        justifyContent: 'center'
    },
    headerTitle: {
        fontSize: 17,
        fontWeight: '600',
        color: '#FFFFFF'
    },
    content: { padding: 20, paddingTop: 32 },
    serviceHeader: { alignItems: 'center', marginBottom: 28 },
    serviceIcon: {
        width: 56,
        height: 56,
        borderRadius: 16,
        alignItems: 'center',
        justifyContent: 'center',
        marginBottom: 12
    },
    serviceName: {
        fontSize: 20,
        fontWeight: '700',
        color: '#0F172A',
        textAlign: 'center',
        marginBottom: 4
    },
    serviceMeta: { fontSize: 13, color: '#64748B' },
    card: {
        backgroundColor: '#FFFFFF',
        borderRadius: 16,
        padding: 16,
        marginBottom: 24,
        shadowColor: '#0F172A',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.06,
        shadowRadius: 8,
        elevation: 2
    },
    cardTitle: {
        fontSize: 14,
        fontWeight: '700',
        color: '#64748B',
        letterSpacing: 0.5,
        marginBottom: 12
    },
    detailRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        paddingVertical: 10,
        borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: 'rgba(0,0,0,0.06)'
    },
    detailLabel: { fontSize: 13, color: '#64748B', flex: 1 },
    detailValue: { fontSize: 13, color: '#0F172A', flex: 2, textAlign: 'right' },
    mono: { fontFamily: 'Inter' },
    removeButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        paddingVertical: 14,
        borderWidth: 1,
        borderColor: '#FF3B30'
    },
    removeButtonDisabled: { opacity: 0.5 },
    removeButtonText: { fontSize: 16, fontWeight: '600', color: '#FF3B30' },
    notFound: { fontSize: 18, textAlign: 'center', marginTop: 100, color: '#64748B' },
    backButton: {
        alignSelf: 'center',
        marginTop: 20,
        backgroundColor: '#007AFF',
        borderRadius: 12,
        paddingHorizontal: 24,
        paddingVertical: 12
    },
    backButtonText: { color: '#fff', fontSize: 16, fontWeight: '600' }
});
