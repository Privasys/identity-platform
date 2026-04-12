// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Consent request screen — shown when an enclave app requests personal data.
 *
 * Triggered via push notification or deep link. Displays what data is being
 * requested, why, and the attestation state of the enclave. The user can
 * approve or deny each attribute individually and optionally set standing
 * consent for the app.
 */

import { Ionicons } from '@expo/vector-icons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useState, useMemo } from 'react';
import {
    StyleSheet,
    ScrollView,
    Pressable,
    View as RNView,
    Switch,
    Alert
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import {
    getAttributeValues,
    recordConsent
} from '@/services/consent';
import type { DataRequest } from '@/services/consent';
import { deliverViaBroker } from '@/services/data-transit';
import { useProfileStore } from '@/stores/profile';

/** Friendly labels for attribute keys. */
const ATTRIBUTE_LABELS: Record<string, string> = {
    displayName: 'Display Name',
    email: 'Email Address',
    avatarUri: 'Profile Photo',
    locale: 'Language / Locale',
    did: 'Decentralised Identifier',
    sub: 'App-Specific Identifier'
};

function attributeLabel(key: string): string {
    return ATTRIBUTE_LABELS[key] ?? key;
}

/** TEE type display. */
function teeLabel(teeType: string): string {
    return teeType === 'sgx' ? 'Intel SGX' : teeType === 'tdx' ? 'Intel TDX' : teeType;
}

export default function ConsentRequestScreen() {
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const params = useLocalSearchParams<{
        rpId: string;
        origin: string;
        appName?: string;
        sessionId: string;
        requestedAttributes: string;
        purpose?: string;
        teeType: string;
        enclaveMeasurement: string;
        codeHash: string;
    }>();

    const request: DataRequest = useMemo(
        () => ({
            rpId: params.rpId ?? '',
            origin: params.origin ?? '',
            appName: params.appName,
            sessionId: params.sessionId ?? '',
            requestedAttributes: params.requestedAttributes
                ? params.requestedAttributes.split(',')
                : [],
            purpose: params.purpose,
            teeType: (params.teeType as 'sgx' | 'tdx') ?? 'sgx',
            enclaveMeasurement: params.enclaveMeasurement ?? '',
            codeHash: params.codeHash ?? ''
        }),
        [params]
    );

    const profile = useProfileStore((s) => s.profile);

    // Per-attribute toggle state — all start approved
    const [approvals, setApprovals] = useState<Record<string, boolean>>(() =>
        Object.fromEntries(request.requestedAttributes.map((k) => [k, true]))
    );

    const [persistent, setPersistent] = useState(false);
    const [submitting, setSubmitting] = useState(false);
    const [showMeasurement, setShowMeasurement] = useState(false);

    const approvedCount = Object.values(approvals).filter(Boolean).length;
    const totalCount = request.requestedAttributes.length;

    const attributeValues = useMemo(
        () => getAttributeValues(request.requestedAttributes),
        [request.requestedAttributes]
    );

    const toggleAttribute = (key: string) => {
        setApprovals((prev) => ({ ...prev, [key]: !prev[key] }));
    };

    const handleApprove = async () => {
        const approved = Object.entries(approvals)
            .filter(([, v]) => v)
            .map(([k]) => k);

        if (approved.length === 0) {
            Alert.alert('No data selected', 'Select at least one attribute to share, or deny the request.');
            return;
        }

        setSubmitting(true);
        try {
            await recordConsent(request, approved, persistent);

            // Deliver approved data to the enclave via broker relay
            if (request.sessionId) {
                const brokerUrl = process.env['EXPO_PUBLIC_BROKER_WS_URL'] ?? '';
                if (brokerUrl) {
                    await deliverViaBroker(approved, {
                        brokerUrl,
                        sessionId: request.sessionId
                    }, request.rpId);
                }
            }

            router.back();
        } catch (e: any) {
            Alert.alert('Error', e.message);
        } finally {
            setSubmitting(false);
        }
    };

    const handleDeny = async () => {
        setSubmitting(true);
        try {
            await recordConsent(request, [], false);
            router.back();
        } catch {
            // Best effort
        } finally {
            setSubmitting(false);
        }
    };

    return (
        <RNView style={styles.screen}>
            {/* Header */}
            <RNView style={[styles.header, { paddingTop: insets.top + 12 }]}>
                <Pressable onPress={() => router.back()} style={styles.closeButton}>
                    <Ionicons name="close" size={24} color="#FFFFFF" />
                </Pressable>
                <Text style={styles.headerTitle}>Data Request</Text>
                <RNView style={{ width: 32 }} />
            </RNView>

            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={styles.scrollContent}
                showsVerticalScrollIndicator={false}
            >
                {/* App identity */}
                <RNView style={styles.appCard}>
                    <RNView style={styles.appIcon}>
                        <Ionicons name="cube-outline" size={28} color="#FFFFFF" />
                    </RNView>
                    <Text style={styles.appName}>
                        {request.appName ?? request.rpId}
                    </Text>
                    <Text style={styles.appOrigin}>{request.origin}</Text>
                    {request.purpose ? (
                        <RNView style={styles.purposeContainer}>
                            <Ionicons name="chatbubble-outline" size={14} color="#64748B" />
                            <Text style={styles.purposeText}>{request.purpose}</Text>
                        </RNView>
                    ) : null}
                </RNView>

                {/* Attestation summary */}
                <Pressable
                    style={styles.attestationCard}
                    onPress={() => setShowMeasurement(!showMeasurement)}
                >
                    <RNView style={styles.attestationHeader}>
                        <RNView style={styles.attestationBadge}>
                            <Ionicons name="shield-checkmark" size={16} color="#34E89E" />
                            <Text style={styles.attestationLabel}>
                                Attested · {teeLabel(request.teeType)}
                            </Text>
                        </RNView>
                        <Ionicons
                            name={showMeasurement ? 'chevron-up' : 'chevron-down'}
                            size={18}
                            color="#94A3B8"
                        />
                    </RNView>
                    {showMeasurement && (
                        <RNView style={styles.measurementDetails}>
                            <Text style={styles.measurementLabel}>Measurement</Text>
                            <Text style={styles.measurementValue} numberOfLines={2}>
                                {request.enclaveMeasurement}
                            </Text>
                            <Text style={styles.measurementLabel}>Code Hash</Text>
                            <Text style={styles.measurementValue} numberOfLines={2}>
                                {request.codeHash}
                            </Text>
                        </RNView>
                    )}
                </Pressable>

                {/* Requested attributes */}
                <Text style={styles.sectionTitle}>REQUESTED DATA</Text>
                <Text style={styles.sectionDescription}>
                    Select which data to share with this app.{' '}
                    {approvedCount} of {totalCount} selected.
                </Text>

                {request.requestedAttributes.map((key) => {
                    const hasValue = key in attributeValues;
                    return (
                        <RNView key={key} style={styles.attributeRow}>
                            <RNView style={styles.attributeInfo}>
                                <Text style={styles.attributeLabel}>
                                    {attributeLabel(key)}
                                </Text>
                                {hasValue ? (
                                    <Text style={styles.attributeValue} numberOfLines={1}>
                                        {attributeValues[key]}
                                    </Text>
                                ) : (
                                    <Text style={styles.attributeMissing}>
                                        Not in your profile
                                    </Text>
                                )}
                            </RNView>
                            <Switch
                                value={approvals[key] && hasValue}
                                onValueChange={() => toggleAttribute(key)}
                                disabled={!hasValue}
                                trackColor={{ false: '#E2E8F0', true: '#34E89E' }}
                                thumbColor="#FFFFFF"
                            />
                        </RNView>
                    );
                })}

                {/* Standing consent toggle */}
                <RNView style={styles.persistentRow}>
                    <RNView style={styles.persistentInfo}>
                        <Text style={styles.persistentLabel}>Always share with this app</Text>
                        <Text style={styles.persistentHint}>
                            Auto-approve future requests while the enclave code stays the same.
                        </Text>
                    </RNView>
                    <Switch
                        value={persistent}
                        onValueChange={setPersistent}
                        trackColor={{ false: '#E2E8F0', true: '#00BCF2' }}
                        thumbColor="#FFFFFF"
                    />
                </RNView>
            </ScrollView>

            {/* Action buttons */}
            <RNView style={[styles.actions, { paddingBottom: insets.bottom + 16 }]}>
                <Pressable
                    style={[styles.denyButton, submitting && styles.disabledButton]}
                    onPress={handleDeny}
                    disabled={submitting}
                >
                    <Text style={styles.denyButtonText}>Deny</Text>
                </Pressable>
                <Pressable
                    style={[
                        styles.approveButton,
                        (submitting || approvedCount === 0) && styles.disabledButton
                    ]}
                    onPress={handleApprove}
                    disabled={submitting || approvedCount === 0}
                >
                    <Ionicons name="shield-checkmark" size={18} color="#FFFFFF" />
                    <Text style={styles.approveButtonText}>
                        Share {approvedCount > 0 ? `(${approvedCount})` : ''}
                    </Text>
                </Pressable>
            </RNView>
        </RNView>
    );
}

const styles = StyleSheet.create({
    screen: { flex: 1, backgroundColor: '#F8FAFB' },

    header: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingHorizontal: 20,
        paddingBottom: 16,
        backgroundColor: '#0F172A'
    },
    closeButton: {
        width: 32,
        height: 32,
        borderRadius: 16,
        backgroundColor: 'rgba(255,255,255,0.12)',
        alignItems: 'center',
        justifyContent: 'center'
    },
    headerTitle: {
        fontSize: 18,
        fontWeight: '700',
        color: '#FFFFFF'
    },

    scrollView: { flex: 1 },
    scrollContent: { padding: 20, paddingBottom: 20 },

    appCard: {
        alignItems: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 16,
        padding: 24,
        marginBottom: 12
    },
    appIcon: {
        width: 56,
        height: 56,
        borderRadius: 28,
        backgroundColor: '#0F172A',
        alignItems: 'center',
        justifyContent: 'center',
        marginBottom: 12
    },
    appName: {
        fontSize: 20,
        fontWeight: '700',
        color: '#0F172A',
        marginBottom: 4
    },
    appOrigin: {
        fontSize: 13,
        color: '#64748B',
        marginBottom: 8
    },
    purposeContainer: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 6,
        backgroundColor: '#F1F5F9',
        borderRadius: 8,
        paddingVertical: 8,
        paddingHorizontal: 12
    },
    purposeText: {
        fontSize: 13,
        color: '#64748B',
        flex: 1,
        lineHeight: 18
    },

    attestationCard: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 14,
        marginBottom: 20
    },
    attestationHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center'
    },
    attestationBadge: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 6
    },
    attestationLabel: {
        fontSize: 14,
        fontWeight: '600',
        color: '#34E89E'
    },
    measurementDetails: {
        marginTop: 12,
        paddingTop: 12,
        borderTopWidth: 0.5,
        borderTopColor: '#F1F5F9'
    },
    measurementLabel: {
        fontSize: 11,
        fontWeight: '600',
        color: '#94A3B8',
        letterSpacing: 0.5,
        marginBottom: 4,
        marginTop: 8
    },
    measurementValue: {
        fontSize: 11,
        fontFamily: 'Inter',
        color: '#64748B',
        lineHeight: 16
    },

    sectionTitle: {
        fontSize: 12,
        fontWeight: '700',
        color: '#94A3B8',
        letterSpacing: 0.8,
        marginBottom: 6
    },
    sectionDescription: {
        fontSize: 13,
        color: '#94A3B8',
        marginBottom: 12,
        lineHeight: 18
    },

    attributeRow: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 8
    },
    attributeInfo: { flex: 1, marginRight: 12 },
    attributeLabel: {
        fontSize: 15,
        fontWeight: '600',
        color: '#0F172A',
        marginBottom: 2
    },
    attributeValue: {
        fontSize: 13,
        color: '#64748B'
    },
    attributeMissing: {
        fontSize: 13,
        color: '#FF9500',
        fontStyle: 'italic'
    },

    persistentRow: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginTop: 16
    },
    persistentInfo: { flex: 1, marginRight: 12 },
    persistentLabel: {
        fontSize: 15,
        fontWeight: '600',
        color: '#0F172A',
        marginBottom: 4
    },
    persistentHint: {
        fontSize: 12,
        color: '#94A3B8',
        lineHeight: 17
    },

    actions: {
        flexDirection: 'row',
        gap: 12,
        paddingHorizontal: 20,
        paddingTop: 12,
        backgroundColor: '#FFFFFF',
        borderTopWidth: 0.5,
        borderTopColor: '#E2E8F0'
    },
    denyButton: {
        flex: 1,
        height: 50,
        borderRadius: 14,
        backgroundColor: '#F1F5F9',
        alignItems: 'center',
        justifyContent: 'center'
    },
    denyButtonText: {
        fontSize: 16,
        fontWeight: '700',
        color: '#64748B'
    },
    approveButton: {
        flex: 2,
        height: 50,
        borderRadius: 14,
        backgroundColor: '#34E89E',
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8
    },
    approveButtonText: {
        fontSize: 16,
        fontWeight: '700',
        color: '#FFFFFF'
    },
    disabledButton: {
        opacity: 0.5
    }
});
