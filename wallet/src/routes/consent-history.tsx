// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Consent history screen — audit trail of all data sharing decisions.
 *
 * Shows a timeline of consent records and computation receipts, filterable
 * by app. Users can review what was shared, when, and revoke standing consents.
 */

import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { useState, useMemo } from 'react';
import {
    StyleSheet,
    ScrollView,
    Pressable,
    View as RNView,
    Alert
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import { useConsentStore, type ConsentRecord, type StandingConsent, type ComputationReceipt } from '@/stores/consent';

/** Decision badge colours. */
const DECISION_COLORS: Record<string, { bg: string; text: string }> = {
    approved: { bg: '#ECFDF5', text: '#059669' },
    denied: { bg: '#FEF2F2', text: '#DC2626' },
    partial: { bg: '#FFFBEB', text: '#D97706' }
};

/** Format epoch seconds to readable date/time. */
function formatDate(epoch: number): string {
    const d = new Date(epoch * 1000);
    return d.toLocaleDateString(undefined, {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

/** Short relative time (e.g. "2h ago", "3d ago"). */
function relativeTime(epoch: number): string {
    const now = Math.floor(Date.now() / 1000);
    const diff = now - epoch;
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return formatDate(epoch);
}

/** Extract unique app names from records. */
function uniqueApps(records: ConsentRecord[]): { rpId: string; name: string }[] {
    const seen = new Map<string, string>();
    for (const r of records) {
        if (!seen.has(r.rpId)) {
            seen.set(r.rpId, r.appName ?? r.rpId);
        }
    }
    return Array.from(seen.entries()).map(([rpId, name]) => ({ rpId, name }));
}

export default function ConsentHistoryScreen() {
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const { records, standingConsents, receipts, removeStandingConsent } = useConsentStore();

    const [filterApp, setFilterApp] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<'history' | 'standing' | 'receipts'>('history');

    const apps = useMemo(() => uniqueApps(records), [records]);

    const filteredRecords = useMemo(
        () => (filterApp ? records.filter((r) => r.rpId === filterApp) : records),
        [records, filterApp]
    );

    const filteredReceipts = useMemo(
        () => (filterApp ? receipts.filter((r) => r.rpId === filterApp) : receipts),
        [receipts, filterApp]
    );

    const handleRevokeStanding = (consent: StandingConsent) => {
        const appName = apps.find((a) => a.rpId === consent.rpId)?.name ?? consent.rpId;
        Alert.alert(
            `Revoke standing consent?`,
            `${appName} will need to request your data again each time.`,
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Revoke',
                    style: 'destructive',
                    onPress: () => removeStandingConsent(consent.rpId)
                }
            ]
        );
    };

    return (
        <RNView style={styles.screen}>
            {/* Header */}
            <RNView style={[styles.header, { paddingTop: insets.top + 12 }]}>
                <Pressable onPress={() => router.back()} style={styles.backButton}>
                    <Ionicons name="chevron-back" size={24} color="#FFFFFF" />
                </Pressable>
                <Text style={styles.headerTitle}>Consent History</Text>
                <RNView style={{ width: 32 }} />
            </RNView>

            {/* Tabs */}
            <RNView style={styles.tabBar}>
                {(['history', 'standing', 'receipts'] as const).map((tab) => (
                    <Pressable
                        key={tab}
                        style={[styles.tab, activeTab === tab && styles.tabActive]}
                        onPress={() => setActiveTab(tab)}
                    >
                        <Text
                            style={[
                                styles.tabText,
                                activeTab === tab && styles.tabTextActive
                            ]}
                        >
                            {tab === 'history'
                                ? `History (${filteredRecords.length})`
                                : tab === 'standing'
                                  ? `Auto-share (${standingConsents.length})`
                                  : `Receipts (${filteredReceipts.length})`}
                        </Text>
                    </Pressable>
                ))}
            </RNView>

            {/* App filter chips */}
            {apps.length > 1 && (
                <ScrollView
                    horizontal
                    showsHorizontalScrollIndicator={false}
                    style={styles.filterContainer}
                    contentContainerStyle={styles.filterContent}
                >
                    <Pressable
                        style={[styles.filterChip, !filterApp && styles.filterChipActive]}
                        onPress={() => setFilterApp(null)}
                    >
                        <Text style={[styles.filterChipText, !filterApp && styles.filterChipTextActive]}>
                            All
                        </Text>
                    </Pressable>
                    {apps.map((app) => (
                        <Pressable
                            key={app.rpId}
                            style={[styles.filterChip, filterApp === app.rpId && styles.filterChipActive]}
                            onPress={() => setFilterApp(filterApp === app.rpId ? null : app.rpId)}
                        >
                            <Text
                                style={[
                                    styles.filterChipText,
                                    filterApp === app.rpId && styles.filterChipTextActive
                                ]}
                                numberOfLines={1}
                            >
                                {app.name}
                            </Text>
                        </Pressable>
                    ))}
                </ScrollView>
            )}

            <ScrollView
                style={styles.scrollView}
                contentContainerStyle={styles.scrollContent}
                showsVerticalScrollIndicator={false}
            >
                {activeTab === 'history' && (
                    <>
                        {filteredRecords.length === 0 ? (
                            <RNView style={styles.emptyState}>
                                <Ionicons name="time-outline" size={48} color="#C7C7CC" />
                                <Text style={styles.emptyTitle}>No consent history</Text>
                                <Text style={styles.emptyText}>
                                    Your data sharing decisions will appear here.
                                </Text>
                            </RNView>
                        ) : (
                            filteredRecords.map((record) => (
                                <ConsentRecordCard key={record.id} record={record} />
                            ))
                        )}
                    </>
                )}

                {activeTab === 'standing' && (
                    <>
                        {standingConsents.length === 0 ? (
                            <RNView style={styles.emptyState}>
                                <Ionicons name="repeat-outline" size={48} color="#C7C7CC" />
                                <Text style={styles.emptyTitle}>No auto-share rules</Text>
                                <Text style={styles.emptyText}>
                                    When you approve "always share" for an app, it will appear here.
                                </Text>
                            </RNView>
                        ) : (
                            standingConsents.map((consent) => (
                                <StandingConsentCard
                                    key={consent.rpId}
                                    consent={consent}
                                    appName={apps.find((a) => a.rpId === consent.rpId)?.name ?? consent.rpId}
                                    onRevoke={() => handleRevokeStanding(consent)}
                                />
                            ))
                        )}
                    </>
                )}

                {activeTab === 'receipts' && (
                    <>
                        {filteredReceipts.length === 0 ? (
                            <RNView style={styles.emptyState}>
                                <Ionicons name="receipt-outline" size={48} color="#C7C7CC" />
                                <Text style={styles.emptyTitle}>No receipts yet</Text>
                                <Text style={styles.emptyText}>
                                    Computation receipts from enclaves will appear here after data processing.
                                </Text>
                            </RNView>
                        ) : (
                            filteredReceipts.map((receipt) => (
                                <ReceiptCard key={receipt.receiptId} receipt={receipt} />
                            ))
                        )}
                    </>
                )}
            </ScrollView>
        </RNView>
    );
}

/** Individual consent record card. */
function ConsentRecordCard({ record }: { record: ConsentRecord }) {
    const [expanded, setExpanded] = useState(false);
    const colors = DECISION_COLORS[record.decision] ?? DECISION_COLORS.denied;

    return (
        <Pressable style={styles.recordCard} onPress={() => setExpanded(!expanded)}>
            <RNView style={styles.recordHeader}>
                <RNView style={styles.recordAppInfo}>
                    <Text style={styles.recordAppName}>
                        {record.appName ?? record.rpId}
                    </Text>
                    <Text style={styles.recordTime}>{relativeTime(record.consentedAt)}</Text>
                </RNView>
                <RNView style={[styles.decisionBadge, { backgroundColor: colors.bg }]}>
                    <Text style={[styles.decisionText, { color: colors.text }]}>
                        {record.decision}
                    </Text>
                </RNView>
            </RNView>

            <RNView style={styles.recordSummary}>
                {record.approvedAttributes.length > 0 && (
                    <RNView style={styles.attributeChips}>
                        <Ionicons name="checkmark-circle" size={14} color="#34E89E" />
                        <Text style={styles.chipText}>
                            {record.approvedAttributes.length} shared
                        </Text>
                    </RNView>
                )}
                {record.deniedAttributes.length > 0 && (
                    <RNView style={styles.attributeChips}>
                        <Ionicons name="close-circle" size={14} color="#FF3B30" />
                        <Text style={styles.chipText}>
                            {record.deniedAttributes.length} denied
                        </Text>
                    </RNView>
                )}
                {record.persistent && (
                    <RNView style={styles.attributeChips}>
                        <Ionicons name="repeat" size={14} color="#00BCF2" />
                        <Text style={styles.chipText}>Auto-share</Text>
                    </RNView>
                )}
            </RNView>

            {expanded && (
                <RNView style={styles.recordDetails}>
                    {record.approvedAttributes.length > 0 && (
                        <>
                            <Text style={styles.detailLabel}>SHARED</Text>
                            {record.approvedAttributes.map((a) => (
                                <Text key={a} style={styles.detailItem}>✓ {a}</Text>
                            ))}
                        </>
                    )}
                    {record.deniedAttributes.length > 0 && (
                        <>
                            <Text style={[styles.detailLabel, { marginTop: 8 }]}>DENIED</Text>
                            {record.deniedAttributes.map((a) => (
                                <Text key={a} style={styles.detailItem}>✗ {a}</Text>
                            ))}
                        </>
                    )}
                    <Text style={[styles.detailLabel, { marginTop: 8 }]}>ENCLAVE</Text>
                    <Text style={styles.detailMono}>
                        {record.teeType.toUpperCase()} · {record.enclaveMeasurement.slice(0, 16)}…
                    </Text>
                    <Text style={styles.detailTimestamp}>{formatDate(record.consentedAt)}</Text>
                </RNView>
            )}
        </Pressable>
    );
}

/** Standing consent card with revoke button. */
function StandingConsentCard({
    consent,
    appName,
    onRevoke
}: {
    consent: StandingConsent;
    appName: string;
    onRevoke: () => void;
}) {
    return (
        <RNView style={styles.standingCard}>
            <RNView style={styles.standingHeader}>
                <RNView style={{ flex: 1 }}>
                    <Text style={styles.standingAppName}>{appName}</Text>
                    <Text style={styles.standingDetail}>
                        Granted {formatDate(consent.grantedAt)}
                    </Text>
                </RNView>
                <Pressable style={styles.revokeButton} onPress={onRevoke}>
                    <Text style={styles.revokeButtonText}>Revoke</Text>
                </Pressable>
            </RNView>
            <RNView style={styles.standingAttributes}>
                {consent.attributes.map((a) => (
                    <RNView key={a} style={styles.standingChip}>
                        <Text style={styles.standingChipText}>{a}</Text>
                    </RNView>
                ))}
            </RNView>
            <Text style={styles.standingMeasurement}>
                Bound to measurement: {consent.enclaveMeasurement.slice(0, 16)}…
            </Text>
        </RNView>
    );
}

/** Computation receipt card. */
function ReceiptCard({ receipt }: { receipt: ComputationReceipt }) {
    const [expanded, setExpanded] = useState(false);

    return (
        <Pressable style={styles.receiptCard} onPress={() => setExpanded(!expanded)}>
            <RNView style={styles.receiptHeader}>
                <Ionicons name="receipt-outline" size={20} color="#00BCF2" />
                <RNView style={{ flex: 1 }}>
                    <Text style={styles.receiptId}>
                        {receipt.receiptId.slice(0, 12)}…
                    </Text>
                    <Text style={styles.receiptTime}>
                        {relativeTime(receipt.receivedAt)}
                    </Text>
                </RNView>
                <Ionicons
                    name={expanded ? 'chevron-up' : 'chevron-down'}
                    size={18}
                    color="#94A3B8"
                />
            </RNView>

            {expanded && (
                <RNView style={styles.receiptDetails}>
                    <Text style={styles.detailLabel}>ENCLAVE</Text>
                    <Text style={styles.detailMono}>{receipt.enclaveId.slice(0, 24)}…</Text>
                    <Text style={styles.detailLabel}>CODE HASH</Text>
                    <Text style={styles.detailMono}>{receipt.codeHash.slice(0, 24)}…</Text>
                    <Text style={styles.detailLabel}>INPUT HASH</Text>
                    <Text style={styles.detailMono}>{receipt.inputHash.slice(0, 24)}…</Text>
                    <Text style={styles.detailLabel}>OUTPUT HASH</Text>
                    <Text style={styles.detailMono}>{receipt.outputHash.slice(0, 24)}…</Text>
                    <Text style={styles.detailLabel}>SIGNATURE</Text>
                    <Text style={styles.detailMono} numberOfLines={2}>
                        {receipt.signature}
                    </Text>
                    <Text style={styles.detailTimestamp}>{receipt.timestamp}</Text>
                </RNView>
            )}
        </Pressable>
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
    backButton: {
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

    tabBar: {
        flexDirection: 'row',
        backgroundColor: '#FFFFFF',
        borderBottomWidth: 0.5,
        borderBottomColor: '#E2E8F0'
    },
    tab: {
        flex: 1,
        alignItems: 'center',
        paddingVertical: 12,
        borderBottomWidth: 2,
        borderBottomColor: 'transparent'
    },
    tabActive: {
        borderBottomColor: '#00BCF2'
    },
    tabText: {
        fontSize: 13,
        fontWeight: '600',
        color: '#94A3B8'
    },
    tabTextActive: {
        color: '#00BCF2'
    },

    filterContainer: {
        maxHeight: 48,
        backgroundColor: '#FFFFFF'
    },
    filterContent: {
        paddingHorizontal: 16,
        paddingVertical: 10,
        gap: 8,
        flexDirection: 'row'
    },
    filterChip: {
        paddingHorizontal: 14,
        paddingVertical: 6,
        borderRadius: 16,
        backgroundColor: '#F1F5F9'
    },
    filterChipActive: {
        backgroundColor: '#0F172A'
    },
    filterChipText: {
        fontSize: 13,
        fontWeight: '600',
        color: '#64748B'
    },
    filterChipTextActive: {
        color: '#FFFFFF'
    },

    scrollView: { flex: 1 },
    scrollContent: { padding: 20, paddingBottom: 40 },

    emptyState: {
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 60,
        gap: 12
    },
    emptyTitle: { fontSize: 18, fontWeight: '600', color: '#0F172A' },
    emptyText: { fontSize: 14, color: '#94A3B8', textAlign: 'center', lineHeight: 20 },

    // Consent record card
    recordCard: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 10
    },
    recordHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: 8
    },
    recordAppInfo: { flex: 1, marginRight: 12 },
    recordAppName: { fontSize: 16, fontWeight: '600', color: '#0F172A', marginBottom: 2 },
    recordTime: { fontSize: 12, color: '#94A3B8' },
    decisionBadge: {
        paddingHorizontal: 10,
        paddingVertical: 4,
        borderRadius: 8
    },
    decisionText: {
        fontSize: 12,
        fontWeight: '700',
        textTransform: 'capitalize'
    },
    recordSummary: {
        flexDirection: 'row',
        gap: 12,
        flexWrap: 'wrap'
    },
    attributeChips: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 4
    },
    chipText: { fontSize: 12, color: '#64748B' },
    recordDetails: {
        marginTop: 12,
        paddingTop: 12,
        borderTopWidth: 0.5,
        borderTopColor: '#F1F5F9'
    },
    detailLabel: {
        fontSize: 10,
        fontWeight: '700',
        color: '#94A3B8',
        letterSpacing: 0.5,
        marginBottom: 4
    },
    detailItem: { fontSize: 13, color: '#0F172A', marginBottom: 2 },
    detailMono: {
        fontSize: 11,
        fontFamily: 'Inter',
        color: '#64748B',
        marginBottom: 8,
        lineHeight: 16
    },
    detailTimestamp: {
        fontSize: 11,
        color: '#94A3B8',
        marginTop: 4
    },

    // Standing consent card
    standingCard: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 10
    },
    standingHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 10
    },
    standingAppName: { fontSize: 16, fontWeight: '600', color: '#0F172A', marginBottom: 2 },
    standingDetail: { fontSize: 12, color: '#94A3B8' },
    revokeButton: {
        paddingHorizontal: 14,
        paddingVertical: 8,
        borderRadius: 8,
        backgroundColor: '#FEF2F2'
    },
    revokeButtonText: {
        fontSize: 13,
        fontWeight: '600',
        color: '#DC2626'
    },
    standingAttributes: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        gap: 6,
        marginBottom: 10
    },
    standingChip: {
        backgroundColor: '#F1F5F9',
        borderRadius: 8,
        paddingHorizontal: 10,
        paddingVertical: 4
    },
    standingChipText: {
        fontSize: 12,
        fontWeight: '500',
        color: '#64748B'
    },
    standingMeasurement: {
        fontSize: 11,
        color: '#94A3B8',
        fontStyle: 'italic'
    },

    // Receipt card
    receiptCard: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 10
    },
    receiptHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12
    },
    receiptId: { fontSize: 14, fontWeight: '600', color: '#0F172A', marginBottom: 2 },
    receiptTime: { fontSize: 12, color: '#94A3B8' },
    receiptDetails: {
        marginTop: 12,
        paddingTop: 12,
        borderTopWidth: 0.5,
        borderTopColor: '#F1F5F9'
    }
});
