// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * "This app requests access to your data" consent UI, shared by the relying-party
 * data-request screen (consent-request) and the KYC identity-verification flow.
 *
 * Presentational only: the caller owns the data and the approve/deny logic. Rows
 * can be plain (an item the app will access, with a leading icon) or toggleable
 * (a profile attribute the user chooses to share). The attestation summary is
 * optional, so a flow that verifies the enclave on a separate page can omit it.
 */

import { Ionicons } from '@expo/vector-icons';
import { useState } from 'react';
import {
    Pressable,
    ScrollView,
    StyleSheet,
    Switch,
    View as RNView,
} from 'react-native';

import { Text } from '@/components/Themed';

export interface ConsentDataItem {
    key: string;
    label: string;
    /** Value preview, "Not in your profile", or a short note. */
    sublabel?: string;
    /** Render the sublabel in a warning colour (e.g. missing). */
    missing?: boolean;
    /** Leading icon for a plain (non-toggle) item. */
    icon?: keyof typeof Ionicons.glyphMap;
    /** When set, the row shows a Switch instead of a leading icon. */
    toggle?: { value: boolean; onChange: () => void; disabled?: boolean };
}

export interface AttestationSummary {
    teeType: string;
    measurement: string;
    codeHash: string;
}

function teeLabel(teeType: string): string {
    return teeType === 'sgx' ? 'Intel SGX' : teeType === 'tdx' ? 'Intel TDX' : teeType;
}

export function DataRequestConsent({
    appName,
    origin,
    purpose,
    appIcon = 'cube-outline',
    attestation,
    expandable = false,
    sectionTitle = 'REQUESTED DATA',
    sectionDescription,
    items,
    note,
    persistent,
    denyLabel = 'Deny',
    approveLabel = 'Share',
    approveCount,
    approveDisabled,
    submitting,
    onDeny,
    onApprove,
    contentBottomInset = 20,
    actionsBottomInset = 16,
    contentTopInset = 0,
}: {
    appName: string;
    origin: string;
    purpose?: string;
    appIcon?: keyof typeof Ionicons.glyphMap;
    attestation?: AttestationSummary;
    /** When true, the attestation summary collapses behind a tap (measurement
     *  hidden by default); otherwise it is always shown. */
    expandable?: boolean;
    sectionTitle?: string;
    sectionDescription?: string;
    items: ConsentDataItem[];
    note?: string;
    persistent?: { value: boolean; onChange: (v: boolean) => void };
    denyLabel?: string;
    approveLabel?: string;
    /** Count shown in the approve button, e.g. "Share (2)". Omit to hide. */
    approveCount?: number;
    approveDisabled?: boolean;
    submitting?: boolean;
    onDeny: () => void;
    onApprove: () => void;
    contentBottomInset?: number;
    actionsBottomInset?: number;
    contentTopInset?: number;
}) {
    const [showMeasurement, setShowMeasurement] = useState(false);
    const showDetails = !expandable || showMeasurement;
    return (
        <RNView style={styles.flex}>
            <ScrollView
                style={styles.flex}
                contentContainerStyle={[styles.scrollContent, { paddingTop: 20 + contentTopInset, paddingBottom: contentBottomInset }]}
                showsVerticalScrollIndicator={false}
            >
                {/* App identity */}
                <RNView style={styles.appCard}>
                    <RNView style={styles.appIcon}>
                        <Ionicons name={appIcon} size={28} color="#FFFFFF" />
                    </RNView>
                    <Text style={styles.appName}>{appName}</Text>
                    <Text style={styles.appOrigin}>{origin}</Text>
                    {purpose ? (
                        <RNView style={styles.purposeContainer}>
                            <Ionicons name="chatbubble-outline" size={14} color="#64748B" />
                            <Text style={styles.purposeText}>{purpose}</Text>
                        </RNView>
                    ) : null}
                </RNView>

                {/* Optional attestation summary (omitted when verified on a separate page) */}
                {attestation ? (
                    <Pressable
                        style={styles.attestationCard}
                        onPress={expandable ? () => setShowMeasurement((v) => !v) : undefined}
                        disabled={!expandable}
                    >
                        <RNView style={styles.attestationHeader}>
                            <RNView style={styles.attestationBadge}>
                                <Ionicons name="shield-checkmark" size={16} color="#34E89E" />
                                <Text style={styles.attestationLabel}>
                                    Attested · {teeLabel(attestation.teeType)}
                                </Text>
                            </RNView>
                            {expandable ? (
                                <Ionicons
                                    name={showMeasurement ? 'chevron-up' : 'chevron-down'}
                                    size={18}
                                    color="#94A3B8"
                                />
                            ) : null}
                        </RNView>
                        {showDetails ? (
                            <RNView style={styles.measurementDetails}>
                                <Text style={styles.measurementLabel}>Measurement</Text>
                                <Text style={styles.measurementValue} numberOfLines={2}>
                                    {attestation.measurement}
                                </Text>
                                {attestation.codeHash ? (
                                    <>
                                        <Text style={styles.measurementLabel}>Code Hash</Text>
                                        <Text style={styles.measurementValue} numberOfLines={2}>
                                            {attestation.codeHash}
                                        </Text>
                                    </>
                                ) : null}
                            </RNView>
                        ) : null}
                    </Pressable>
                ) : null}

                {/* Requested data */}
                <Text style={styles.sectionTitle}>{sectionTitle}</Text>
                {sectionDescription ? (
                    <Text style={styles.sectionDescription}>{sectionDescription}</Text>
                ) : null}

                {items.map((item) => (
                    <RNView key={item.key} style={styles.attributeRow}>
                        {item.toggle ? null : item.icon ? (
                            <Ionicons name={item.icon} size={20} color="#0F172A" style={styles.itemIcon} />
                        ) : null}
                        <RNView style={styles.attributeInfo}>
                            <Text style={styles.attributeLabel}>{item.label}</Text>
                            {item.sublabel ? (
                                <Text style={item.missing ? styles.attributeMissing : styles.attributeValue} numberOfLines={1}>
                                    {item.sublabel}
                                </Text>
                            ) : null}
                        </RNView>
                        {item.toggle ? (
                            <Switch
                                value={item.toggle.value}
                                onValueChange={item.toggle.onChange}
                                disabled={item.toggle.disabled}
                                trackColor={{ false: '#E2E8F0', true: '#34E89E' }}
                                thumbColor="#FFFFFF"
                            />
                        ) : null}
                    </RNView>
                ))}

                {/* Standing consent */}
                {persistent ? (
                    <RNView style={styles.persistentRow}>
                        <RNView style={styles.persistentInfo}>
                            <Text style={styles.persistentLabel}>Always share with this app</Text>
                            <Text style={styles.persistentHint}>
                                Auto-approve future requests while the enclave code stays the same.
                            </Text>
                        </RNView>
                        <Switch
                            value={persistent.value}
                            onValueChange={persistent.onChange}
                            trackColor={{ false: '#E2E8F0', true: '#00BCF2' }}
                            thumbColor="#FFFFFF"
                        />
                    </RNView>
                ) : null}

                {note ? <Text style={styles.note}>{note}</Text> : null}
            </ScrollView>

            {/* Actions */}
            <RNView style={[styles.actions, { paddingBottom: actionsBottomInset }]}>
                <Pressable
                    style={[styles.denyButton, submitting && styles.disabledButton]}
                    onPress={onDeny}
                    disabled={submitting}
                >
                    <Text style={styles.denyButtonText}>{denyLabel}</Text>
                </Pressable>
                <Pressable
                    style={[styles.approveButton, (submitting || approveDisabled) && styles.disabledButton]}
                    onPress={onApprove}
                    disabled={submitting || approveDisabled}
                >
                    <Ionicons name="shield-checkmark" size={18} color="#FFFFFF" />
                    <Text style={styles.approveButtonText}>
                        {approveLabel}{approveCount !== undefined ? ` (${approveCount})` : ''}
                    </Text>
                </Pressable>
            </RNView>
        </RNView>
    );
}

const styles = StyleSheet.create({
    flex: { flex: 1 },
    scrollContent: { padding: 20 },

    appCard: { alignItems: 'center', backgroundColor: '#FFFFFF', borderRadius: 16, padding: 24, marginBottom: 12 },
    appIcon: {
        width: 56, height: 56, borderRadius: 28, backgroundColor: '#0F172A',
        alignItems: 'center', justifyContent: 'center', marginBottom: 12,
    },
    appName: { fontSize: 20, fontWeight: '700', color: '#0F172A', marginBottom: 4 },
    appOrigin: { fontSize: 13, color: '#64748B', marginBottom: 8 },
    purposeContainer: {
        flexDirection: 'row', alignItems: 'center', gap: 6, backgroundColor: '#F1F5F9',
        borderRadius: 8, paddingVertical: 8, paddingHorizontal: 12,
    },
    purposeText: { fontSize: 13, color: '#64748B', flex: 1, lineHeight: 18 },

    attestationCard: { backgroundColor: '#FFFFFF', borderRadius: 12, padding: 14, marginBottom: 20 },
    attestationHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
    attestationBadge: { flexDirection: 'row', alignItems: 'center', gap: 6 },
    attestationLabel: { fontSize: 14, fontWeight: '600', color: '#34E89E' },
    measurementDetails: { marginTop: 12, paddingTop: 12, borderTopWidth: 0.5, borderTopColor: '#F1F5F9' },
    measurementLabel: { fontSize: 11, fontWeight: '600', color: '#94A3B8', letterSpacing: 0.5, marginBottom: 4, marginTop: 8 },
    measurementValue: { fontSize: 11, fontFamily: 'Inter', color: '#64748B', lineHeight: 16 },

    sectionTitle: { fontSize: 12, fontWeight: '700', color: '#94A3B8', letterSpacing: 0.8, marginBottom: 6 },
    sectionDescription: { fontSize: 13, color: '#94A3B8', marginBottom: 12, lineHeight: 18 },

    attributeRow: {
        flexDirection: 'row', alignItems: 'center', backgroundColor: '#FFFFFF',
        borderRadius: 12, padding: 16, marginBottom: 8, gap: 12,
    },
    itemIcon: { width: 22 },
    attributeInfo: { flex: 1 },
    attributeLabel: { fontSize: 15, fontWeight: '600', color: '#0F172A', marginBottom: 2 },
    attributeValue: { fontSize: 13, color: '#64748B' },
    attributeMissing: { fontSize: 13, color: '#FF9500', fontStyle: 'italic' },

    persistentRow: {
        flexDirection: 'row', alignItems: 'center', backgroundColor: '#FFFFFF',
        borderRadius: 12, padding: 16, marginTop: 16,
    },
    persistentInfo: { flex: 1, marginRight: 12 },
    persistentLabel: { fontSize: 15, fontWeight: '600', color: '#0F172A', marginBottom: 4 },
    persistentHint: { fontSize: 12, color: '#94A3B8', lineHeight: 17 },

    note: { fontSize: 13, color: '#94A3B8', textAlign: 'center', marginTop: 16, lineHeight: 18 },

    actions: {
        flexDirection: 'row', gap: 12, paddingHorizontal: 20, paddingTop: 12, paddingBottom: 16,
        backgroundColor: '#FFFFFF', borderTopWidth: 0.5, borderTopColor: '#E2E8F0',
    },
    denyButton: { flex: 1, height: 50, borderRadius: 14, backgroundColor: '#F1F5F9', alignItems: 'center', justifyContent: 'center' },
    denyButtonText: { fontSize: 16, fontWeight: '700', color: '#64748B' },
    approveButton: {
        flex: 2, height: 50, borderRadius: 14, backgroundColor: '#34E89E',
        flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: 8,
    },
    approveButtonText: { fontSize: 16, fontWeight: '700', color: '#FFFFFF' },
    disabledButton: { opacity: 0.5 },
});
