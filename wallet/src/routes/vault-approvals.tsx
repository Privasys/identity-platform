// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Vault approvals screen.
 *
 * Lists pending vault operations (a promote/export the user initiated from the
 * CLI/portal) that need a fresh, operation-bound hardware approval. The live set
 * is held in stores/vaultApprovals (shared with the Home banner); each entry was
 * learned by its capability (vault_op) from a push or the notification tray. The
 * wallet resolves which of its on-device pairwise credentials the request targets
 * and signs the operation-bound WebAuthn challenge after an explicit biometric
 * gate.
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
    approveVaultApproval,
    resolveApprovalCredential,
    type VaultApprovalRequest,
} from '@/services/vault-approval-api';
import { useVaultApprovalsStore } from '@/stores/vaultApprovals';

function shortHandle(handle: string): string {
    const parts = handle.split('/');
    return parts.length >= 2 ? `${parts[1].slice(0, 12)}…` : handle;
}
function shortHex(hex: string): string {
    if (!hex) return '—';
    return hex.length > 20 ? `${hex.slice(0, 10)}…${hex.slice(-6)}` : hex;
}
/** Human countdown to expiry (expires_at is epoch seconds). */
function formatRemaining(expiresAtSec: number, nowMs: number): string {
    const secs = Math.max(0, Math.round(expiresAtSec - nowMs / 1000));
    if (secs <= 0) return 'Expired';
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return m > 0 ? `Expires in ${m}m ${s}s` : `Expires in ${s}s`;
}

export default function VaultApprovalsScreen() {
    const params = useLocalSearchParams<{ vault_op?: string }>();

    const pending = useVaultApprovalsStore((s) => s.pending);
    const loading = useVaultApprovalsStore((s) => s.loading);
    const refresh = useVaultApprovalsStore((s) => s.refresh);
    const remember = useVaultApprovalsStore((s) => s.remember);
    const forget = useVaultApprovalsStore((s) => s.forget);

    const [refreshing, setRefreshing] = useState(false);
    const [approvingOp, setApprovingOp] = useState<string | null>(null);
    const [now, setNow] = useState(() => Date.now());

    // Arriving via a push deep-link: register the capability, then refresh.
    useEffect(() => {
        if (params.vault_op) remember(params.vault_op);
        void refresh();
    }, [params.vault_op, remember, refresh]);

    // Tick so the expiry countdown stays live.
    useEffect(() => {
        const id = setInterval(() => setNow(Date.now()), 1000);
        return () => clearInterval(id);
    }, []);

    const onRefresh = useCallback(async () => {
        setRefreshing(true);
        await refresh();
        setRefreshing(false);
    }, [refresh]);

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
                forget(req.vault_op);
                Alert.alert('Approved', 'The operation is authorised. Your terminal will continue automatically.');
            } catch (e: any) {
                Alert.alert('Approval failed', e?.message ?? 'Could not complete the approval.');
            } finally {
                setApprovingOp(null);
            }
        },
        [forget],
    );

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title="Vault approvals" />
            <ScrollView
                contentContainerStyle={styles.content}
                refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#34E89E" />}
            >
                <Text style={styles.subtitle}>
                    Approve an operation you started from the CLI or portal. Each approval authorises exactly one
                    operation.
                </Text>

                {loading && pending.length === 0 ? (
                    <ActivityIndicator style={styles.spinner} color="#34E89E" />
                ) : pending.length === 0 ? (
                    <RNView style={styles.emptyCard}>
                        <RNView style={styles.emptyIcon}>
                            <Ionicons name="checkmark-circle" size={30} color="#34E89E" />
                        </RNView>
                        <Text style={styles.emptyTitle}>No pending approvals</Text>
                        <Text style={styles.emptyBody}>
                            Requests appear here for a few minutes after you start an operation that needs your
                            approval. If one expired, restart it from your terminal.
                        </Text>
                    </RNView>
                ) : (
                    pending.map((req) => {
                        const highlighted = params.vault_op === req.vault_op;
                        const busy = approvingOp === req.vault_op;
                        const remaining = formatRemaining(req.expires_at, now);
                        const urgent = req.expires_at - now / 1000 < 60;
                        return (
                            <RNView key={req.vault_op} style={[styles.card, highlighted && styles.cardHighlighted]}>
                                <RNView style={styles.cardHeader}>
                                    <RNView style={styles.cardTitleWrap}>
                                        <RNView style={styles.cardIcon}>
                                            <Ionicons name="key" size={16} color="#0F766E" />
                                        </RNView>
                                        <Text style={styles.cardTitle}>
                                            {req.summary.operation === 'promote'
                                                ? 'Approve new version'
                                                : req.summary.operation === 'export'
                                                  ? 'Approve key export'
                                                  : 'Approve operation'}
                                        </Text>
                                    </RNView>
                                    <RNView style={[styles.ttlPill, urgent && styles.ttlPillUrgent]}>
                                        <Ionicons
                                            name="time-outline"
                                            size={12}
                                            color={urgent ? '#B45309' : '#0F766E'}
                                        />
                                        <Text style={[styles.ttlText, urgent && styles.ttlTextUrgent]}>
                                            {remaining}
                                        </Text>
                                    </RNView>
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
                                        <>
                                            <Ionicons name="finger-print" size={18} color="#FFFFFF" />
                                            <Text style={styles.approveText}>Approve</Text>
                                        </>
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
        borderRadius: 16,
        padding: 28,
        alignItems: 'center',
        gap: 10,
        shadowColor: '#0F172A',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.06,
        shadowRadius: 8,
        elevation: 2,
    },
    emptyIcon: {
        width: 56,
        height: 56,
        borderRadius: 28,
        backgroundColor: 'rgba(52, 232, 158, 0.12)',
        alignItems: 'center',
        justifyContent: 'center',
    },
    emptyTitle: { fontSize: 16, fontWeight: '600', color: '#0F172A' },
    emptyBody: { fontSize: 13, lineHeight: 19, color: '#64748B', textAlign: 'center' },
    card: {
        backgroundColor: '#FFFFFF',
        borderRadius: 16,
        padding: 16,
        marginBottom: 14,
        shadowColor: '#0F172A',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.06,
        shadowRadius: 8,
        elevation: 2,
    },
    cardHighlighted: { borderWidth: 1, borderColor: '#34E89E' },
    cardHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 14,
    },
    cardTitleWrap: { flexDirection: 'row', alignItems: 'center', gap: 8, flexShrink: 1 },
    cardIcon: {
        width: 28,
        height: 28,
        borderRadius: 8,
        backgroundColor: 'rgba(52, 232, 158, 0.12)',
        alignItems: 'center',
        justifyContent: 'center',
    },
    cardTitle: { fontSize: 15, fontWeight: '600', color: '#0F172A', flexShrink: 1 },
    ttlPill: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 4,
        backgroundColor: 'rgba(52, 232, 158, 0.12)',
        paddingHorizontal: 8,
        paddingVertical: 3,
        borderRadius: 10,
    },
    ttlPillUrgent: { backgroundColor: '#FEF3C7' },
    ttlText: { fontSize: 12, fontWeight: '600', color: '#0F766E' },
    ttlTextUrgent: { color: '#B45309' },
    row: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
    label: { fontSize: 13, color: '#64748B' },
    value: { fontSize: 14, fontWeight: '600', color: '#0F172A' },
    mono: { fontSize: 12, color: '#334155', fontFamily: 'monospace' },
    approveBtn: {
        flexDirection: 'row',
        gap: 8,
        backgroundColor: '#34E89E',
        borderRadius: 12,
        paddingVertical: 13,
        alignItems: 'center',
        justifyContent: 'center',
        marginTop: 8,
    },
    approveBtnDisabled: { opacity: 0.6 },
    approveText: { color: '#FFFFFF', fontWeight: '700', fontSize: 15 },
});
