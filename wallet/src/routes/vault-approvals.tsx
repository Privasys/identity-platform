// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Vault approvals screen.
 *
 * Lists pending vault operations (a promote/export the owner initiated from the
 * CLI) that need a fresh, operation-bound hardware approval. The owner reviews
 * the operation, confirms with biometric, and the wallet signs the operation-
 * bound WebAuthn challenge with its existing fido2 credential and posts it to the
 * IdP — which issues the token the CLI is waiting for. See vault-approval-api.ts.
 */

import { Ionicons } from '@expo/vector-icons';
import { useLocalSearchParams } from 'expo-router';
import * as LocalAuthentication from 'expo-local-authentication';
import { useCallback, useEffect, useState } from 'react';
import { StyleSheet, ScrollView, Pressable, View as RNView, Alert, ActivityIndicator, RefreshControl } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text } from '@/components/Themed';
import { ensurePrivasysSession } from '@/services/privasys-id';
import { listVaultApprovals, approveVaultApproval, type VaultApprovalRequest } from '@/services/vault-approval-api';
import { useAuthStore } from '@/stores/auth';

function shortHandle(handle: string): string {
    const parts = handle.split('/');
    return parts.length >= 2 ? parts[1].slice(0, 12) + '…' : handle;
}
function shortHex(hex: string): string {
    if (!hex) return '—';
    return hex.length > 20 ? `${hex.slice(0, 10)}…${hex.slice(-6)}` : hex;
}

export default function VaultApprovalsScreen() {
    const insets = useSafeAreaInsets();
    const params = useLocalSearchParams<{ vault_op?: string }>();
    const privasysId = useAuthStore((s) => s.privasysId);
    const walletSessionToken = privasysId?.sessionToken ?? '';

    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [requests, setRequests] = useState<VaultApprovalRequest[]>([]);
    const [approvingOp, setApprovingOp] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    const load = useCallback(async () => {
        setError(null);
        try {
            // Refresh the session (silent if still valid; biometric otherwise).
            const { sessionToken } = await ensurePrivasysSession();
            const pending = await listVaultApprovals(sessionToken);
            setRequests(pending);
        } catch (e: any) {
            setError(e?.message ?? 'Could not load vault approvals');
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    }, []);

    useEffect(() => {
        void load();
    }, [load]);

    const onRefresh = useCallback(() => {
        setRefreshing(true);
        void load();
    }, [load]);

    const approve = useCallback(
        async (req: VaultApprovalRequest) => {
            if (!privasysId?.keyAlias || !privasysId?.credentialId) {
                Alert.alert('No credential', 'This device has no Privasys ID credential to approve with.');
                return;
            }
            const biometric = await LocalAuthentication.authenticateAsync({
                promptMessage: 'Approve vault operation',
                cancelLabel: 'Cancel',
            });
            if (!biometric.success) return;

            setApprovingOp(req.vault_op);
            try {
                await approveVaultApproval(req, privasysId.keyAlias, privasysId.credentialId);
                setRequests((prev) => prev.filter((r) => r.vault_op !== req.vault_op));
                Alert.alert('Approved', 'The operation is authorised. Return to your terminal — it will continue automatically.');
            } catch (e: any) {
                Alert.alert('Approval failed', e?.message ?? 'Could not complete the approval.');
            } finally {
                setApprovingOp(null);
            }
        },
        [privasysId],
    );

    return (
        <ScrollView
            style={styles.screen}
            contentContainerStyle={{ paddingTop: insets.top + 12, paddingBottom: insets.bottom + 24, paddingHorizontal: 16 }}
            refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#8891a8" />}
        >
            <RNView style={styles.header}>
                <Ionicons name="shield-checkmark-outline" size={22} color="#4f7cff" />
                <Text style={styles.title}>Vault approvals</Text>
            </RNView>
            <Text style={styles.subtitle}>
                Approve an operation you started from the CLI. Each approval authorises exactly one operation.
            </Text>

            {!walletSessionToken ? (
                <Text style={styles.empty}>Sign in to your Privasys ID to see pending approvals.</Text>
            ) : loading ? (
                <ActivityIndicator style={{ marginTop: 32 }} color="#8891a8" />
            ) : error ? (
                <Text style={styles.error}>{error}</Text>
            ) : requests.length === 0 ? (
                <Text style={styles.empty}>No pending approvals.</Text>
            ) : (
                requests.map((req) => {
                    const highlighted = params.vault_op && req.vault_op === params.vault_op;
                    return (
                        <RNView key={req.vault_op} style={[styles.card, highlighted && styles.cardHighlighted]}>
                            <RNView style={styles.row}>
                                <Text style={styles.opLabel}>Operation</Text>
                                <Text style={styles.opValue}>{req.summary.operation}</Text>
                            </RNView>
                            <RNView style={styles.row}>
                                <Text style={styles.opLabel}>App key</Text>
                                <Text style={styles.opValue}>{shortHandle(req.summary.handle)}</Text>
                            </RNView>
                            {req.summary.measurement ? (
                                <RNView style={styles.row}>
                                    <Text style={styles.opLabel}>New measurement</Text>
                                    <Text style={styles.mono}>{shortHex(req.summary.measurement)}</Text>
                                </RNView>
                            ) : null}
                            <Pressable
                                style={[styles.approveBtn, approvingOp === req.vault_op && styles.approveBtnDisabled]}
                                disabled={approvingOp === req.vault_op}
                                onPress={() => approve(req)}
                            >
                                {approvingOp === req.vault_op ? (
                                    <ActivityIndicator color="#fff" />
                                ) : (
                                    <Text style={styles.approveText}>Approve with biometric</Text>
                                )}
                            </Pressable>
                        </RNView>
                    );
                })
            )}
        </ScrollView>
    );
}

const styles = StyleSheet.create({
    screen: { flex: 1, backgroundColor: '#0b0c10' },
    header: { flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 6 },
    title: { fontSize: 20, fontWeight: '700', color: '#e8eaf0' },
    subtitle: { fontSize: 13, lineHeight: 19, color: '#aab0c0', marginBottom: 18 },
    empty: { fontSize: 14, color: '#8891a8', marginTop: 32, textAlign: 'center' },
    error: { fontSize: 14, color: '#ff6b6b', marginTop: 24 },
    card: { backgroundColor: '#14161d', borderColor: '#262a36', borderWidth: 1, borderRadius: 14, padding: 16, marginBottom: 14 },
    cardHighlighted: { borderColor: '#4f7cff' },
    row: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
    opLabel: { fontSize: 13, color: '#8891a8' },
    opValue: { fontSize: 14, color: '#e8eaf0', fontWeight: '600' },
    mono: { fontSize: 12, color: '#c8cde0', fontFamily: 'monospace' },
    approveBtn: { backgroundColor: '#4f7cff', borderRadius: 10, paddingVertical: 12, alignItems: 'center', marginTop: 8 },
    approveBtnDisabled: { opacity: 0.6 },
    approveText: { color: '#fff', fontWeight: '700', fontSize: 15 },
});
