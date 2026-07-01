// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Enclave attestation viewer — the "Verify Enclave" screen the user sees during
 * every sign-in ceremony (RA-TLS attestation result + full TEE properties, with
 * Approve / Reject). Shared so other flows that send data to an enclave (e.g. the
 * KYC identity-verifier flow) present the *same* familiar verification step.
 */

import { useState } from 'react';
import { Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text, View } from '@/components/Themed';
import type { AttestationDiff } from '@/services/attestation-diff';
import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';

/**
 * Why we trust the current attestation.
 *
 * - `fresh-as-verified`: just round-tripped to as.privasys.org with an
 *   App Attest-bound token. Highest assurance; required on first connect
 *   to a new enclave and periodically after that.
 * - `cached-trusted`: the cert measurements match a previously-verified
 *   record in the trusted-apps store and the cache is still within TTL.
 *   We did not re-contact the attestation server.
 * - `non-enclave`: the cert carried no TEE measurements (e.g. github.com
 *   behind a Let's Encrypt cert). The wallet supports FIDO2 sign-in to
 *   non-enclave RPs; attestation simply does not apply.
 */
export type AttestationVerificationLevel =
    | 'fresh-as-verified'
    | 'cached-trusted'
    | 'non-enclave';

const CHANGED_TITLES: Record<AttestationDiff['kind'], string> = {
    'app-update': 'App Updated',
    'platform-update': 'Platform Updated',
    'app-and-platform-update': 'App & Platform Changed',
};

export function AttestationView({
    attestation,
    rpId,
    displayName,
    isChanged,
    diff,
    verificationLevel,
    onApprove,
    onReject,
}: {
    attestation: AttestationResult;
    rpId: string;
    /** Human-readable app name shown above the origin (caller-derived). */
    displayName: string;
    isChanged: boolean;
    /**
     * Field-level change breakdown vs the trusted record (attestation-changed
     * step only). Drives the kind-specific title, the summary sentence and the
     * "What changed" card; without it the changed state falls back to the
     * generic warning.
     */
    diff?: AttestationDiff | null;
    verificationLevel: AttestationVerificationLevel | null;
    onApprove: () => void;
    onReject: () => void;
}) {
    const [detailsOpen, setDetailsOpen] = useState(false);
    const insets = useSafeAreaInsets();
    const appType = attestation.tee_type === 'sgx' ? 'WASM Application' : 'Container Application';
    const teeColor = attestation.tee_type === 'sgx' ? '#34E89E' : '#00BCF2';
    const changedTitle = (diff && CHANGED_TITLES[diff.kind]) || 'App Changed';

    return (
        <RNView style={{ flex: 1 }}>
            <ScrollView contentContainerStyle={[styles.attestationContainer, { paddingBottom: 100 + insets.bottom }]}>
                {isChanged && (
                    <View style={styles.warningBanner}>
                        <Text style={styles.warningText}>
                            {diff
                                ? `⚠ ${diff.summary}`
                                : "⚠ This app's attestation has changed since you last verified it."}
                        </Text>
                    </View>
                )}

                <Text style={styles.title}>{isChanged ? changedTitle : 'Verify Enclave'}</Text>
                <Text style={styles.attestationAppName}>{displayName}</Text>
                <Text style={styles.attestationOrigin}>{rpId}</Text>

                {/* Verification Status */}
                <View
                    style={[
                        styles.statusBanner,
                        attestation.valid ? styles.statusBannerValid : styles.statusBannerInvalid,
                    ]}
                >
                    <Text style={styles.statusIcon}>{attestation.valid ? '✓' : '✕'}</Text>
                    <View style={styles.statusInfo}>
                        <Text
                            style={[
                                styles.statusTitle,
                                attestation.valid ? styles.statusTitleValid : styles.statusTitleInvalid,
                            ]}
                        >
                            {attestation.valid ? 'Attestation Valid' : 'Attestation Invalid'}
                        </Text>
                        <Text style={styles.statusDetail}>
                            {appType} · {attestation.tee_type?.toUpperCase()} enclave
                        </Text>
                    </View>
                    <View style={[styles.teeBadge, { backgroundColor: teeColor }]}>
                        <Text style={styles.teeBadgeText}>{attestation.tee_type?.toUpperCase()}</Text>
                    </View>
                </View>

                {/* Verification-level badge — surfaces whether we just contacted
                    the attestation server or trusted a recent local cache. */}
                {verificationLevel === 'fresh-as-verified' && (
                    <View style={[styles.verifyBadge, styles.verifyBadgeFresh]}>
                        <Text style={styles.verifyBadgeIcon}>✓</Text>
                        <Text style={styles.verifyBadgeText}>Verified just now by as.privasys.org</Text>
                    </View>
                )}
                {verificationLevel === 'cached-trusted' && (
                    <View style={[styles.verifyBadge, styles.verifyBadgeCached]}>
                        <Text style={styles.verifyBadgeIcon}>↻</Text>
                        <Text style={styles.verifyBadgeText}>Trusted from a recent verification on this device</Text>
                    </View>
                )}

                {/* What changed — always visible on the changed step, so the
                    user approves a specific, named change rather than a
                    generic warning. */}
                {isChanged && diff && diff.changes.length > 0 && (
                    <>
                        <Text style={styles.sectionHeader}>What Changed</Text>
                        <View style={styles.attestationCard}>
                            {diff.changes.map((c) => (
                                <View key={c.label} style={styles.changeRow}>
                                    <Text style={styles.changeLabel}>{c.label}</Text>
                                    <View style={styles.changeValues}>
                                        <Text style={styles.changeOld} selectable>
                                            {c.previous ? truncateHex(c.previous) : 'not recorded'}
                                        </Text>
                                        <Text style={styles.changeArrow}>→</Text>
                                        <Text style={styles.changeNew} selectable>
                                            {c.current ? truncateHex(c.current) : 'removed'}
                                        </Text>
                                    </View>
                                </View>
                            ))}
                        </View>
                    </>
                )}

                {/* Collapsible details toggle */}
                <Pressable style={styles.detailsToggle} onPress={() => setDetailsOpen(!detailsOpen)}>
                    <Text style={styles.detailsToggleText}>
                        {detailsOpen ? 'Hide details' : 'Show attestation details'}
                    </Text>
                    <Text style={styles.detailsToggleIcon}>{detailsOpen ? '▲' : '▼'}</Text>
                </Pressable>

                {detailsOpen && (
                    <>
                        {/* Verification Details */}
                        {(attestation.quote_verification_status ||
                            attestation.attestation_servers_hash ||
                            attestation.workload_key_source) && (
                            <>
                                <Text style={styles.sectionHeader}>Verification</Text>
                                <View style={styles.attestationCard}>
                                    {attestation.quote_verification_status && (
                                        <AttestationRow label="Quote Status" value={attestation.quote_verification_status} />
                                    )}
                                    {attestation.attestation_servers_hash && (
                                        <AttestationRow label="Attestation Server" value={truncateHex(attestation.attestation_servers_hash)} />
                                    )}
                                    {attestation.workload_key_source && (
                                        <AttestationRow label="Key Source" value={attestation.workload_key_source} />
                                    )}
                                </View>
                            </>
                        )}

                        {/* Enclave Identity */}
                        <Text style={styles.sectionHeader}>Enclave Identity</Text>
                        <View style={styles.attestationCard}>
                            {attestation.mrenclave && (
                                <AttestationRow label="MRENCLAVE" value={truncateHex(attestation.mrenclave)} />
                            )}
                            {attestation.mrsigner && (
                                <AttestationRow label="MRSIGNER" value={truncateHex(attestation.mrsigner)} />
                            )}
                            {attestation.mrtd && <AttestationRow label="MRTD" value={truncateHex(attestation.mrtd)} />}
                            {attestation.workload_code_hash && (
                                <AttestationRow label="Code Hash" value={truncateHex(attestation.workload_code_hash)} />
                            )}
                            {attestation.workload_config_merkle_root && (
                                <AttestationRow label="Config Root" value={truncateHex(attestation.workload_config_merkle_root)} />
                            )}
                        </View>

                        {/* Certificate */}
                        <Text style={styles.sectionHeader}>Certificate</Text>
                        <View style={styles.attestationCard}>
                            <AttestationRow label="Subject" value={attestation.cert_subject} />
                            <AttestationRow label="Valid From" value={attestation.cert_not_before} />
                            <AttestationRow label="Valid Until" value={attestation.cert_not_after} />
                        </View>

                        {/* Advisory IDs */}
                        {attestation.advisory_ids && attestation.advisory_ids.length > 0 && (
                            <>
                                <Text style={styles.sectionHeader}>Advisories</Text>
                                <View style={styles.attestationCard}>
                                    {attestation.advisory_ids.map((id) => (
                                        <AttestationRow key={id} label={id} value="Known advisory" />
                                    ))}
                                </View>
                            </>
                        )}

                        {/* Custom OIDs */}
                        {attestation.custom_oids && attestation.custom_oids.length > 0 && (
                            <>
                                <Text style={styles.sectionHeader}>Custom Extensions</Text>
                                <View style={styles.attestationCard}>
                                    {attestation.custom_oids.map((oid) => (
                                        <AttestationRow key={oid.oid} label={oid.label || oid.oid} value={truncateHex(oid.value_hex)} />
                                    ))}
                                </View>
                            </>
                        )}
                    </>
                )}
            </ScrollView>

            {/* Fixed bottom action buttons */}
            <RNView style={[styles.bottomActions, { paddingBottom: Math.max(insets.bottom, 20) }]}>
                <View style={styles.buttonRow}>
                    <Pressable style={styles.rejectButton} onPress={onReject}>
                        <Text style={styles.rejectButtonText}>Reject</Text>
                    </Pressable>
                    <Pressable style={styles.approveButton} onPress={onApprove}>
                        <Text style={styles.approveButtonText}>
                            {isChanged ? (diff ? 'Approve Changes' : 'Trust Anyway') : 'Approve'}
                        </Text>
                    </Pressable>
                </View>
            </RNView>
        </RNView>
    );
}

function AttestationRow({ label, value }: { label: string; value?: string }) {
    if (!value) return null;
    return (
        <View style={styles.attestationRow}>
            <Text style={styles.attestationLabel}>{label}</Text>
            <Text style={styles.attestationValue} selectable>
                {value}
            </Text>
        </View>
    );
}

export function truncateHex(hex: string): string {
    if (hex.length <= 16) return hex;
    return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}

const styles = StyleSheet.create({
    attestationContainer: { padding: 20, paddingTop: 80 },
    title: { fontSize: 24, fontWeight: 'bold', textAlign: 'center', marginBottom: 8 },
    attestationAppName: { fontSize: 22, fontWeight: '700', textAlign: 'center', marginBottom: 4 },
    attestationOrigin: { fontSize: 12, color: '#94A3B8', textAlign: 'center', fontFamily: 'Inter', marginBottom: 20 },
    detailsToggle: {
        flexDirection: 'row', alignItems: 'center', justifyContent: 'center', paddingVertical: 14,
        marginBottom: 8, borderRadius: 10, backgroundColor: 'rgba(0,0,0,0.04)', gap: 8,
    },
    detailsToggleText: { fontSize: 14, fontWeight: '500', color: '#64748B' },
    detailsToggleIcon: { fontSize: 10, color: '#94A3B8' },
    bottomActions: {
        position: 'absolute', bottom: 0, left: 0, right: 0, paddingHorizontal: 20, paddingTop: 16,
        backgroundColor: '#F8FAFB', borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: 'rgba(0,0,0,0.1)',
    },
    warningBanner: { backgroundColor: '#FFF3CD', borderRadius: 8, padding: 12, marginBottom: 16 },
    warningText: { color: '#856404', fontSize: 14, textAlign: 'center' },
    statusBanner: { flexDirection: 'row', alignItems: 'center', borderRadius: 12, padding: 16, marginBottom: 24, gap: 12 },
    statusBannerValid: { backgroundColor: '#E8FFF0' },
    statusBannerInvalid: { backgroundColor: '#FFF1F0' },
    statusIcon: { fontSize: 28, fontWeight: '700' },
    statusInfo: { flex: 1, backgroundColor: 'transparent' },
    statusTitle: { fontSize: 16, fontWeight: '700' },
    statusTitleValid: { color: '#166534' },
    statusTitleInvalid: { color: '#991B1B' },
    statusDetail: { fontSize: 13, color: '#64748B', marginTop: 2 },
    teeBadge: { paddingHorizontal: 10, paddingVertical: 4, borderRadius: 6 },
    teeBadgeText: { color: '#fff', fontSize: 12, fontWeight: '700', letterSpacing: 0.5 },
    verifyBadge: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 12, paddingVertical: 8, borderRadius: 8, marginBottom: 12, gap: 8 },
    verifyBadgeFresh: { backgroundColor: '#E8FFF0', borderWidth: 1, borderColor: '#34D399' },
    verifyBadgeCached: { backgroundColor: '#F1F5F9', borderWidth: 1, borderColor: '#CBD5E1' },
    verifyBadgeIcon: { fontSize: 14, fontWeight: '700', color: '#0F766E' },
    verifyBadgeText: { fontSize: 13, fontWeight: '500', color: '#0F172A', flex: 1 },
    sectionHeader: {
        fontSize: 13, fontWeight: '600', color: '#94A3B8', textTransform: 'uppercase',
        letterSpacing: 0.5, marginBottom: 8, marginTop: 4,
    },
    attestationCard: { backgroundColor: '#FFFFFF', borderRadius: 12, padding: 16, marginBottom: 16 },
    attestationRow: {
        flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 8,
        borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: 'rgba(128,128,128,0.3)', backgroundColor: 'transparent',
    },
    attestationLabel: { fontSize: 13, opacity: 0.6, flex: 1 },
    attestationValue: { fontSize: 13, fontFamily: 'Inter', flex: 2, textAlign: 'right' },
    changeRow: {
        paddingVertical: 8, borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: 'rgba(128,128,128,0.3)', backgroundColor: 'transparent',
    },
    changeLabel: { fontSize: 13, fontWeight: '600', marginBottom: 4 },
    changeValues: { flexDirection: 'row', alignItems: 'center', gap: 6, backgroundColor: 'transparent' },
    changeOld: { fontSize: 12, fontFamily: 'Inter', color: '#94A3B8', textDecorationLine: 'line-through' },
    changeArrow: { fontSize: 12, color: '#64748B' },
    changeNew: { fontSize: 12, fontFamily: 'Inter', fontWeight: '600' },
    buttonRow: { flexDirection: 'row', justifyContent: 'space-between', gap: 12 },
    approveButton: { flex: 1, backgroundColor: '#34C759', borderRadius: 12, paddingVertical: 14, alignItems: 'center' },
    approveButtonText: { color: '#fff', fontSize: 17, fontWeight: '600' },
    rejectButton: { flex: 1, backgroundColor: 'rgba(128,128,128,0.2)', borderRadius: 12, paddingVertical: 14, alignItems: 'center' },
    rejectButtonText: { fontSize: 17, fontWeight: '600' },
});
