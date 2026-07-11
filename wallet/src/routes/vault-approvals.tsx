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
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
    StyleSheet,
    ScrollView,
    Pressable,
    View as RNView,
    Alert,
    ActivityIndicator,
    Linking,
    Platform,
    RefreshControl,
} from 'react-native';

import * as NativeKeys from '../../modules/native-keys/src/index';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { fetchReleaseProvenance, type ReleaseProvenance } from '@/services/release-provenance';
import {
    approveVaultApproval,
    resolveApprovalCredential,
    type VaultApprovalRequest,
} from '@/services/vault-approval-api';
import { useServiceSessionsStore } from '@/stores/service-sessions';
import { useVaultApprovalsStore } from '@/stores/vaultApprovals';

function shortHandle(handle: string): string {
    const parts = handle.split('/');
    return parts.length >= 2 ? `${parts[1].slice(0, 12)}…` : handle;
}
function shortHex(hex: string): string {
    if (!hex) return '—';
    return hex.length > 20 ? `${hex.slice(0, 10)}…${hex.slice(-6)}` : hex;
}

/** A tappable row that opens a release / compare URL in the browser. */
function ReleaseLinkRow({
    icon,
    label,
    value,
    url,
}: {
    icon: keyof typeof Ionicons.glyphMap;
    label: string;
    value: string;
    url: string;
}) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    return (
        <Pressable style={styles.row} onPress={() => void Linking.openURL(url)}>
            <Text style={styles.label}>{label}</Text>
            <RNView style={styles.linkValueWrap}>
                <Text style={styles.linkValue} numberOfLines={1}>
                    {value}
                </Text>
                <Ionicons name={icon} size={13} color={p.infoText} />
                <Ionicons name="open-outline" size={13} color={p.infoText} />
            </RNView>
        </Pressable>
    );
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
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);

    const pending = useVaultApprovalsStore((s) => s.pending);
    const loading = useVaultApprovalsStore((s) => s.loading);
    const refresh = useVaultApprovalsStore((s) => s.refresh);
    const remember = useVaultApprovalsStore((s) => s.remember);
    const forget = useVaultApprovalsStore((s) => s.forget);

    const [refreshing, setRefreshing] = useState(false);
    const [approvingOp, setApprovingOp] = useState<string | null>(null);
    const [now, setNow] = useState(() => Date.now());
    // Release provenance keyed by vault_op — fetched from mgmt (public) for each
    // promote that carries app_id + version_id, so the user can open the
    // published release and the exact code diff before approving.
    const [provenance, setProvenance] = useState<Record<string, ReleaseProvenance>>({});

    useEffect(() => {
        let cancelled = false;
        for (const req of pending) {
            const s = req.summary;
            if (
                s.operation !== 'promote' ||
                !s.app_id ||
                !s.version_id ||
                provenance[req.vault_op] !== undefined
            ) {
                continue;
            }
            void fetchReleaseProvenance(s.app_id, s.version_id).then((p) => {
                if (!cancelled && p) {
                    setProvenance((prev) => ({ ...prev, [req.vault_op]: p }));
                }
            });
        }
        return () => {
            cancelled = true;
        };
    }, [pending, provenance]);

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
            // One fresh biometric for the whole approval. On iOS the
            // operation-bound signature (approveVaultApproval → NativeKeys.sign)
            // is itself Face ID-gated by the Secure Enclave, so a separate
            // expo prompt here made it two; authenticating our own signing
            // context instead lets that signature ride this same Face ID. On
            // Android the hardware signature doesn't prompt again, so the OS
            // biometric shown here is already the only one.
            const approved =
                Platform.OS === 'ios'
                    ? await NativeKeys.authenticateForSigning('Approve vault operation')
                    : (
                          await LocalAuthentication.authenticateAsync({
                              promptMessage: 'Approve vault operation',
                              cancelLabel: 'Cancel',
                          })
                      ).success;
            if (!approved) return;

            setApprovingOp(req.vault_op);
            try {
                await approveVaultApproval(req, credential);
                // Audit trail: a one-shot, operation-bound authentication.
                useServiceSessionsStore.getState().record({
                    serviceKey: 'privasys-enclave-vault',
                    displayName: 'Enclave Vault',
                    kind: 'approval',
                    identity: 'privasys-id',
                    rpId: req.options.publicKey.rpId ?? 'privasys.id',
                    origin: 'privasys.id',
                    channel: 'push',
                    startedAt: Date.now(),
                    oneShot: true,
                    detail:
                        req.summary.operation === 'promote'
                            ? `Approved a new version for key ${req.summary.handle}`
                            : req.summary.operation === 'export'
                              ? `Approved a key export for ${req.summary.handle}`
                              : `Approved a vault operation on ${req.summary.handle}`
                });
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
                refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={p.green} />}
            >
                <Text style={styles.subtitle}>
                    Approve an operation you started from the CLI or portal. Each approval authorises exactly one
                    operation.
                </Text>

                {loading && pending.length === 0 ? (
                    <ActivityIndicator style={styles.spinner} color={p.green} />
                ) : pending.length === 0 ? (
                    <RNView style={styles.emptyCard}>
                        <RNView style={styles.emptyIcon}>
                            <Ionicons name="checkmark-circle" size={30} color={p.green} />
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
                        const s = req.summary;
                        const subject = s.app_name || shortHandle(s.handle);
                        return (
                            <RNView key={req.vault_op} style={[styles.card, highlighted && styles.cardHighlighted]}>
                                <RNView style={styles.cardHeader}>
                                    <RNView style={styles.cardTitleWrap}>
                                        <RNView style={styles.cardIcon}>
                                            <Ionicons name="key" size={16} color={p.infoText} />
                                        </RNView>
                                        <Text style={styles.cardTitle}>
                                            {s.operation === 'promote'
                                                ? 'Approve new version'
                                                : s.operation === 'export'
                                                  ? 'Approve key export'
                                                  : 'Approve operation'}
                                        </Text>
                                    </RNView>
                                    <RNView style={[styles.ttlPill, urgent && styles.ttlPillUrgent]}>
                                        <Ionicons
                                            name="time-outline"
                                            size={12}
                                            color={urgent ? p.warnText : p.infoText}
                                        />
                                        <Text style={[styles.ttlText, urgent && styles.ttlTextUrgent]}>
                                            {remaining}
                                        </Text>
                                    </RNView>
                                </RNView>

                                {/* Subject: the app (friendly name if the initiator
                                    supplied it), then the plain-language action. */}
                                <Text style={styles.subject}>{subject}</Text>
                                <Text style={styles.plain}>
                                    {s.operation === 'promote'
                                        ? s.app_name
                                            ? 'Authorise this app to release its data key to the new version below. Only approve an upgrade you started.'
                                            : 'Authorise the enclave to release its data key to the new measurement below. Only approve an upgrade you started.'
                                        : s.operation === 'export'
                                          ? 'Authorise a one-time export of this key’s material. Only approve if you are exporting it yourself.'
                                          : 'Approve this vault operation only if you started it.'}
                                </Text>

                                {s.version ? (
                                    <RNView style={styles.row}>
                                        <Text style={styles.label}>Version</Text>
                                        <Text style={styles.value}>{s.version}</Text>
                                    </RNView>
                                ) : null}

                                {/* Published release + the exact code changes since
                                    the last promoted version. mgmt-resolved from the
                                    catalogue (verified by Privasys), so the user can
                                    read the diff before approving an upgrade. */}
                                {(() => {
                                    const prov = provenance[req.vault_op];
                                    if (!prov) return null;
                                    const rel = prov.workload_release;
                                    const relLabel = prov.version?.label ?? rel?.label;
                                    return (
                                        <>
                                            {rel?.url ? (
                                                <ReleaseLinkRow
                                                    icon="cube-outline"
                                                    label="Published release"
                                                    value={relLabel ?? 'View'}
                                                    url={rel.url}
                                                />
                                            ) : null}
                                            {prov.previous?.compare_url ? (
                                                <ReleaseLinkRow
                                                    icon="git-compare-outline"
                                                    label="Code changes"
                                                    value={
                                                        prov.previous.label && relLabel
                                                            ? `${prov.previous.label} → ${relLabel}`
                                                            : 'View diff'
                                                    }
                                                    url={prov.previous.compare_url}
                                                />
                                            ) : null}
                                        </>
                                    );
                                })()}
                                {s.key_type ? (
                                    <RNView style={styles.row}>
                                        <Text style={styles.label}>Key type</Text>
                                        <Text style={styles.value}>{s.key_type}</Text>
                                    </RNView>
                                ) : null}
                                <RNView style={styles.row}>
                                    <Text style={styles.label}>App key</Text>
                                    <Text style={styles.value}>{shortHandle(s.handle)}</Text>
                                </RNView>
                                {typeof s.policy_version === 'number' ? (
                                    <RNView style={styles.row}>
                                        <Text style={styles.label}>Policy version</Text>
                                        <Text style={styles.value}>{s.policy_version}</Text>
                                    </RNView>
                                ) : null}
                                {s.measurement ? (
                                    <RNView style={styles.row}>
                                        <Text style={styles.label}>New measurement</Text>
                                        <Text style={styles.mono}>{shortHex(s.measurement)}</Text>
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

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    content: { padding: 16, paddingBottom: 40 },
    subtitle: { fontSize: 13, lineHeight: 19, color: p.textSecondary, marginBottom: 16 },
    spinner: { marginTop: 40 },
    emptyCard: {
        backgroundColor: p.card,
        borderRadius: 16,
        padding: 28,
        alignItems: 'center',
        gap: 10,
        shadowColor: '#000',
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
    emptyTitle: { fontSize: 16, fontWeight: '600', color: p.textPrimary },
    emptyBody: { fontSize: 13, lineHeight: 19, color: p.textSecondary, textAlign: 'center' },
    card: {
        backgroundColor: p.card,
        borderRadius: 16,
        padding: 16,
        marginBottom: 14,
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.06,
        shadowRadius: 8,
        elevation: 2,
    },
    cardHighlighted: { borderWidth: 1, borderColor: p.green },
    subject: { fontSize: 17, fontWeight: '700', color: p.textPrimary, marginBottom: 4 },
    plain: { fontSize: 13, lineHeight: 19, color: p.textSecondary, marginBottom: 12 },
    linkValueWrap: { flexDirection: 'row', alignItems: 'center', gap: 5, flexShrink: 1 },
    linkValue: { fontSize: 14, fontWeight: '600', color: p.infoText, flexShrink: 1 },
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
    cardTitle: { fontSize: 15, fontWeight: '600', color: p.textPrimary, flexShrink: 1 },
    ttlPill: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 4,
        backgroundColor: 'rgba(52, 232, 158, 0.12)',
        paddingHorizontal: 8,
        paddingVertical: 3,
        borderRadius: 10,
    },
    ttlPillUrgent: { backgroundColor: p.warnBg },
    ttlText: { fontSize: 12, fontWeight: '600', color: p.infoText },
    ttlTextUrgent: { color: p.warnText },
    row: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
    label: { fontSize: 13, color: p.textSecondary },
    value: { fontSize: 14, fontWeight: '600', color: p.textPrimary },
    mono: { fontSize: 12, color: p.textSecondary, fontFamily: 'monospace' },
    approveBtn: {
        flexDirection: 'row',
        gap: 8,
        backgroundColor: p.green,
        borderRadius: 12,
        paddingVertical: 13,
        alignItems: 'center',
        justifyContent: 'center',
        marginTop: 8,
    },
    approveBtnDisabled: { opacity: 0.6 },
    approveText: { color: '#FFFFFF', fontWeight: '700', fontSize: 15 },
});
