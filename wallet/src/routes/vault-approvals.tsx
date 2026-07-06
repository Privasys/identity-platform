// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Vault approvals screen.
 *
 * Lists pending vault operations (a promote/export the user initiated from the
 * CLI/portal) that need a fresh, operation-bound hardware approval. Each entry
 * is fetched by its capability (vault_op from the push); the wallet resolves
 * which of its on-device pairwise credentials the request targets and signs the
 * operation-bound WebAuthn challenge after an explicit biometric gate.
 */

import { Ionicons } from '@expo/vector-icons';
import * as LocalAuthentication from 'expo-local-authentication';
import { useLocalSearchParams } from 'expo-router';
import { useCallback, useEffect, useState } from 'react';
import {
    StyleSheet,
    ScrollView,
    Pressable,
    View as RNView,
    Alert,
    ActivityIndicator,
    RefreshControl,
} from 'react-native';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text } from '@/components/Themed';
import {
    fetchVaultApproval,
    approveVaultApproval,
    resolveApprovalCredential,
    rememberVaultOp,
    forgetVaultOp,
    knownVaultOpsList,
    type VaultApprovalRequest,
} from '@/services/vault-approval-api';

function shortHandle(handle: string): string {
    const parts = handle.split('/');
    return parts.length >= 2 ? `${parts[1].slice(0, 12)}…` : handle;
}
function shortHex(hex: string): string {
    if (!hex) return '—';
    return hex.length > 20 ? `${hex.slice(0, 10)}…${hex.slice(-6)}` : hex;
}

export default function VaultApprovalsScreen() {
    const params = useLocalSearchParams<{ vault_op?: string }>();

    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [requests, setRequests] = useState<VaultApprovalRequest[]>([]);
    const [approvingOp, setApprovingOp] = useState<string | null>(null);

    const load = useCallback(async () => {
        if (params.vault_op) rememberVaultOp(params.vault_op);
        const ops = knownVaultOpsList();
        const found: VaultApprovalRequest[] = [];
        await Promise.all(
            ops.map(async (op) => {
                try {
                    const req = await fetchVaultApproval(op);
                    if (req) found.push(req);
                    else forgetVaultOp(op); // approved or expired
                } catch (e) {
                    console.warn('[vault-approvals] fetch failed', e);
                }
            }),
        );
        found.sort((a, b) => b.expires_at - a.expires_at);
        setRequests(found);
        setLoading(false);
        setRefreshing(false);
    }, [params.vault_op]);

    useEffect(() => {
        void load();
    }, [load]);

    const onRefresh = useCallback(() => {
        setRefreshing(true);
        void load();
    }, [load]);

    const approve = useCallback(
        async (req: VaultApprovalRequest) => {
            const credential = resolveApprovalCredential(req);
            if (!credential) {
                Alert.alert(
                    'Wrong device or identity',
                    'This request targets a credential this device does not hold. Approve it from the device you used to register with the platform.',
                );
                return;
            }
            const biometric = await LocalAuthentication.authenticateAsync({
                promptMessage: 'Approve vault operation',
                cancelLabel: 'Cancel',
            });
            if (!biometric.success) return;

            setApprovingOp(req.vault_op);
            try {
                await approveVaultApproval(req, credential);
                forgetVaultOp(req.vault_op);
                setRequests((prev) => prev.filter((r) => r.vault_op !== req.vault_op));
                Alert.alert('Approved', 'The operation is authorised. Your terminal will continue automatically.');
            } catch (e: any) {
                Alert.alert('Approval failed', e?.message ?? 'Could not complete the approval.');
            } finally {
                setApprovingOp(null);
            }
        },
        [],
    );

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title="Vault approvals" />
            <ScrollView
                contentContainerStyle={styles.content}
                refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
            >
                <Text style={styles.subtitle}>
                    Approve an operation you started from the CLI or portal. Each approval authorises exactly one
                    operation.
                </Text>

                {loading ? (
                    <ActivityIndicator style={styles.spinner} color="#34E89E" />
                ) : requests.length === 0 ? (
                    <RNView style={styles.emptyCard}>
                        <Ionicons name="checkmark-circle-outline" size={28} color="#34E89E" />
                        <Text style={styles.emptyTitle}>No pending approvals</Text>
                        <Text style={styles.emptyBody}>
                            Requests appear here for a few minutes after you start an operation that needs your
                            approval. If one expired, restart it from your terminal.
                        </Text>
                    </RNView>
                ) : (
                    requests.map((req) => {
                        const highlighted = params.vault_op === req.vault_op;
                        const busy = approvingOp === req.vault_op;
                        return (
                            <RNView key={req.vault_op} style={[styles.card, highlighted && styles.cardHighlighted]}>
                                <RNView style={styles.cardHeader}>
                                    <Ionicons name="key-outline" size={18} color="#0F172A" />
                                    <Text style={styles.cardTitle}>
                                        {req.summary.operation === 'promote'
                                            ? 'Approve new version'
                                            : req.summary.operation === 'export'
                                              ? 'Approve key export'
                                              : 'Approve operation'}
                                    </Text>
                                </RNView>
                                <RNView style={styles.row}>
                                    <Text style={styles.label}>App key</Text>
                                    <Text style={styles.value}>{shortHandle(req.summary.handle)}</Text>
                                </RNView>
                                {req.summary.measurement ? (
                                    <RNView style={styles.row}>
                                        <Text style={styles.label}>New measurement</Text>
                                        <Text style={styles.mono}>{shortHex(req.summary.measurement)}</Text>
                                    </RNView>
                                ) : null}
                                <Pressable
                                    style={[styles.approveBtn, busy && styles.approveBtnDisabled]}
                                    disabled={busy}
                                    onPress={() => approve(req)}
                                >
                                    {busy ? (
                                        <ActivityIndicator color="#FFFFFF" />
                                    ) : (
                                        <Text style={styles.approveText}>Approve</Text>
                                    )}
                                </Pressable>
                            </RNView>
                        );
                    })
                )}
            </ScrollView>
        </RNView>
    );
}

const styles = StyleSheet.create({
    screen: { flex: 1, backgroundColor: '#F8FAFB' },
    content: { padding: 16, paddingBottom: 40 },
    subtitle: { fontSize: 13, lineHeight: 19, color: '#64748B', marginBottom: 16 },
    spinner: { marginTop: 40 },
    emptyCard: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 24,
        alignItems: 'center',
        gap: 8,
    },
    emptyTitle: { fontSize: 15, fontWeight: '600', color: '#0F172A' },
    emptyBody: { fontSize: 13, lineHeight: 19, color: '#64748B', textAlign: 'center' },
    card: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 14,
    },
    cardHighlighted: { borderWidth: 1, borderColor: '#34E89E' },
    cardHeader: { flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 12 },
    cardTitle: { fontSize: 15, fontWeight: '600', color: '#0F172A' },
    row: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
    label: { fontSize: 13, color: '#64748B' },
    value: { fontSize: 14, fontWeight: '600', color: '#0F172A' },
    mono: { fontSize: 12, color: '#334155', fontFamily: 'monospace' },
    approveBtn: {
        backgroundColor: '#34E89E',
        borderRadius: 12,
        paddingVertical: 13,
        alignItems: 'center',
        marginTop: 8,
    },
    approveBtnDisabled: { opacity: 0.6 },
    approveText: { color: '#FFFFFF', fontWeight: '700', fontSize: 15 },
});
