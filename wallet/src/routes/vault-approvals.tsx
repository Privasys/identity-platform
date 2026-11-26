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

import Ionicons from '@expo/vector-icons/Ionicons';
import { router, useLocalSearchParams } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
    StyleSheet,
    ScrollView,
    Pressable,
    View as RNView,
    Alert,
    ActivityIndicator,
    Linking,
    RefreshControl,
} from 'react-native';


import { SubPageHeader } from '@/components/SubPageHeader';
import { taskStyles } from '@/components/task-styles';
import { VaultBatchCard } from '@/components/VaultBatchCard';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { fetchReleaseProvenance, type ReleaseProvenance } from '@/services/release-provenance';
import {
    approveVaultApproval,
    describeApprovalMismatch,
    resolveApprovalCredential,
    type VaultApprovalRequest,
} from '@/services/vault-approval-api';
import { checkReshare, forgetPublishedReleases, vaultReleaseFor, type VaultRelease } from '@/services/vault-reshare';
import { checkV1, checkV2, checkV2Release, isV2, requiresV2 } from '@/services/vault-approval-v2';
import { computeVaultOp } from '@/services/vault-approval-batch';
import { billingPlatform, type BillingPlatform } from '@/services/platforms';
import { PERSON_OPS, policyDiff, policyFacts, type Gate, type PersonOp } from '@/services/vault-policy-view';
import { sha256 } from '@noble/hashes/sha2.js';
import { notify } from '@/stores/notice';
import { freshBiometric } from '@/services/approval-answer';
import { useServiceSessionsStore } from '@/stores/service-sessions';
import { useVaultApprovalsStore } from '@/stores/vaultApprovals';
import { useActiveRoute } from '@/utils/active-route';
import { MONO } from '@/constants/fonts';

function shortHandle(handle: string): string {
    const parts = handle.split('/');
    return parts.length >= 2 ? `${parts[1].slice(0, 12)}…` : handle;
}
function shortHex(hex: string, t: TFunction): string {
    if (!hex) return t('common.none');
    return hex.length > 20 ? `${hex.slice(0, 10)}…${hex.slice(-6)}` : hex;
}

const OP_LABEL: Record<PersonOp, string> = {
    PromoteProfile: 'vaultApprovals.policyOpPromote',
    UpdatePolicy: 'vaultApprovals.policyOpUpdate',
    DeleteKey: 'vaultApprovals.policyOpDelete',
    ExportKey: 'vaultApprovals.policyOpExport',
};

function gateText(gate: Gate, t: TFunction): string {
    return t(
        gate === 'approval'
            ? 'vaultApprovals.policyGateApproval'
            : gate === 'open'
              ? 'vaultApprovals.policyGateOpen'
              : 'vaultApprovals.policyGateNone',
    );
}

type CardStyles = ReturnType<typeof makeStyles>;

/**
 * A key's rules as facts: who owns it, who else may approve, which builds
 * can use it, and what needs the owner's approval. The rules were tied to
 * what the approval signs before this is shown.
 */
function PolicyFactRows({ policy, t, styles }: { policy: unknown; t: TFunction; styles: CardStyles }) {
    let facts;
    try {
        facts = policyFacts(policy);
    } catch {
        return null;
    }
    const row = (key: string, label: string, value: string) => (
        <RNView key={key} style={styles.row}>
            <Text style={styles.label}>{label}</Text>
            <Text style={styles.value}>{value}</Text>
        </RNView>
    );
    return (
        <RNView testID="vault-policy-facts">
            {facts.owner ? row('owner', t('vaultApprovals.policyOwner'), facts.owner) : null}
            {facts.approvers.length > 0 ? row('approvers', t('vaultApprovals.policyApprovers'), facts.approvers.join(', ')) : null}
            {row('builds', t('vaultApprovals.policyBuilds'), facts.builds.length > 0 ? facts.builds.join(', ') : t('common.none'))}
            {PERSON_OPS.map((op) => row(op, t(OP_LABEL[op]), gateText(facts.gates[op], t)))}
            {row('updates', t('vaultApprovals.policyFollowsUpdates'), t(facts.followsUpdates ? 'common.yes' : 'common.no'))}
        </RNView>
    );
}

/**
 * What changes between the rules in force and the new ones, fact by fact.
 * Shown only when the approval binds both, so the change is what is signed.
 */
function PolicyChangeRows({ current, next, t, styles }: { current: unknown; next: unknown; t: TFunction; styles: CardStyles }) {
    let diff;
    try {
        diff = policyDiff(current, next);
    } catch {
        return null;
    }
    const none = t('common.none');
    const row = (key: string, label: string, value: string) => (
        <RNView key={key} style={styles.row}>
            <Text style={styles.label}>{label}</Text>
            <Text style={styles.value}>{value}</Text>
        </RNView>
    );
    const yesNo = (v: boolean) => t(v ? 'common.yes' : 'common.no');
    return (
        <RNView style={styles.summaryBox} testID="vault-policy-changes">
            <Text style={styles.summaryLabel}>{t('vaultApprovals.batchWhatChanges')}</Text>
            {diff.changes.map((c) => {
                switch (c.kind) {
                    case 'owner':
                        return row('owner', t('vaultApprovals.policyOwner'), `${c.before ?? none} → ${c.after ?? none}`);
                    case 'approvers':
                        return row(
                            'approvers',
                            t('vaultApprovals.policyApprovers'),
                            `${c.before.join(', ') || none} → ${c.after.join(', ') || none}`,
                        );
                    case 'builds':
                        return (
                            <RNView key="builds">
                                {c.added.length > 0
                                    ? row('added', t('vaultApprovals.policyBuilds'), t('vaultApprovals.policyBuildAdded', { builds: c.added.join(', ') }))
                                    : null}
                                {c.removed.length > 0
                                    ? row('removed', t('vaultApprovals.policyBuilds'), t('vaultApprovals.policyBuildRemoved', { builds: c.removed.join(', ') }))
                                    : null}
                            </RNView>
                        );
                    case 'gate':
                        return row(c.op, t(OP_LABEL[c.op]), `${gateText(c.before, t)} → ${gateText(c.after, t)}`);
                    case 'followsUpdates':
                        return row('updates', t('vaultApprovals.policyFollowsUpdates'), `${yesNo(c.before)} → ${yesNo(c.after)}`);
                }
            })}
            <Text style={styles.summaryText}>
                {t(diff.other ? 'vaultApprovals.policyOtherChanges' : 'vaultApprovals.policyNothingElse')}
            </Text>
        </RNView>
    );
}

/** A key's own name within its app: its kind and generation, e.g. "storage-kek/v2". */
function shortKeyName(handle: string): string {
    const parts = handle.split('/').filter(Boolean);
    return parts.length >= 2 ? parts.slice(-2).join('/') : handle;
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
/**
 * A key renewal (reshare), checked: the target vault build is approvable only
 * once its fields recompute to the bound measurement AND it is a published
 * Enclave Vault release.
 */
type ReshareCheck =
    | { kind: 'checking' }
    | { kind: 'ok'; release: VaultRelease; vaults: number; threshold: number }
    /** The fields do not recompute to what the approval binds. */
    | { kind: 'mismatch' }
    /** The build is no published release. */
    | { kind: 'unpublished'; mrenclave: string }
    /** GitHub could not be reached for a build not pinned in this wallet. */
    | { kind: 'unreachable' };

async function checkReshareRequest(req: VaultApprovalRequest): Promise<ReshareCheck> {
    const checked = checkReshare(req.summary);
    if (!checked) return { kind: 'mismatch' };
    try {
        const release = await vaultReleaseFor(checked.mrenclave);
        if (!release) return { kind: 'unpublished', mrenclave: checked.mrenclave };
        return { kind: 'ok', release, vaults: checked.vaults.length, threshold: checked.threshold };
    } catch {
        return { kind: 'unreachable' };
    }
}

/**
 * An approval on binding v2, checked: approvable only once what it shows is
 * what it would sign, every vault it names has an identity that agrees with
 * itself, and those vaults run a published Enclave Vault release.
 */
type V2Check =
    | { kind: 'checking' }
    | {
          kind: 'ok';
          release: VaultRelease;
          vaults: number;
          platform: BillingPlatform;
          successor?: string;
          /** The rules the approval installs, and the ones in force when it binds them too. */
          newPolicy?: unknown;
          currentPolicy?: unknown;
      }
    | { kind: 'mismatch' }
    | { kind: 'unpublished'; build: string }
    | { kind: 'unreachable' };

async function checkV2Request(req: VaultApprovalRequest): Promise<V2Check> {
    const checked = checkV2(req.vault_op, req.summary, Math.floor(Date.now() / 1000));
    if (!checked) return { kind: 'mismatch' };
    const release = await checkV2Release(checked, typeof req.summary.vault_release === 'string' ? req.summary.vault_release : undefined);
    if (release.kind === 'ok') {
        const sha256Hex = (text: string) =>
            Array.from(sha256(new TextEncoder().encode(text)), (b) => b.toString(16).padStart(2, '0')).join('');
        const platform = await billingPlatform(checked.billingIds, sha256Hex);
        return {
            kind: 'ok',
            release: release.release,
            vaults: checked.members.length,
            platform,
            successor: checked.successor,
            newPolicy: checked.newPolicy,
            currentPolicy: checked.currentPolicy,
        };
    }
    return release;
}

/** Human countdown to expiry (expires_at is epoch seconds). */
function formatRemaining(expiresAtSec: number, nowMs: number, t: TFunction): string {
    const secs = Math.max(0, Math.round(expiresAtSec - nowMs / 1000));
    if (secs <= 0) return t('vaultApprovals.expired');
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    // Two separate keys rather than an optional minutes clause: the unit
    // order and spacing differ by language.
    return m > 0
        ? t('vaultApprovals.expiresInMinutes', { minutes: m, seconds: s })
        : t('vaultApprovals.expiresInSeconds', { count: s });
}

/** One route, as the deep link names it: a batch id opens that list's card. */
export default function VaultApprovalsRoute() {
    const { batch_id: batchId } = useLocalSearchParams<{ batch_id?: string }>();
    return batchId ? <VaultBatchCard key={String(batchId)} batchId={String(batchId)} /> : <VaultApprovalsScreen />;
}

function VaultApprovalsScreen() {
    // A list screen: while it is up, a fresh push has nothing to add beyond the
    // store update that precedes it, so the dispatcher skips the route push
    // rather than stacking another copy of this same view.
    useActiveRoute('/vault-approvals');
    const params = useLocalSearchParams<{ vault_op?: string }>();
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const task = useMemo(() => taskStyles(p), [p]);

    const pending = useVaultApprovalsStore((s) => s.pending);
    const decline = useVaultApprovalsStore((s) => s.decline);
    const loading = useVaultApprovalsStore((s) => s.loading);
    const discover = useVaultApprovalsStore((s) => s.discover);
    const remember = useVaultApprovalsStore((s) => s.remember);
    const forget = useVaultApprovalsStore((s) => s.forget);
    const batchIds = useVaultApprovalsStore((s) => s.batchIds);

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

    // Key renewals, checked before Approve is offered (services/vault-reshare).
    // Each is checked once; a pull to refresh checks again the ones that could
    // not be approved (GitHub unreachable, or a release published since).
    const [reshares, setReshares] = useState<Record<string, ReshareCheck>>({});
    const reshareStarted = useRef(new Set<string>());
    const [recheck, setRecheck] = useState(0);
    useEffect(() => {
        for (const req of pending) {
            if (req.summary.operation !== 'reshare' || reshareStarted.current.has(req.vault_op)) continue;
            reshareStarted.current.add(req.vault_op);
            void checkReshareRequest(req).then((c) => setReshares((prev) => ({ ...prev, [req.vault_op]: c })));
        }
    }, [pending, recheck]);
    // Approvals on binding v2, checked the same way before Approve is offered.
    const [v2Checks, setV2Checks] = useState<Record<string, V2Check>>({});
    const v2Started = useRef(new Set<string>());
    useEffect(() => {
        for (const req of pending) {
            if (!isV2(req.summary) || v2Started.current.has(req.vault_op)) continue;
            v2Started.current.add(req.vault_op);
            void checkV2Request(req).then((c) => setV2Checks((prev) => ({ ...prev, [req.vault_op]: c })));
        }
    }, [pending, recheck]);
    const recheckReshares = useCallback(() => {
        forgetPublishedReleases();
        setV2Checks((prev) => {
            const kept: Record<string, V2Check> = {};
            for (const [op, c] of Object.entries(prev)) {
                if (c.kind === 'ok' || c.kind === 'mismatch') kept[op] = c;
                else v2Started.current.delete(op);
            }
            return kept;
        });
        setReshares((prev) => {
            const kept: Record<string, ReshareCheck> = {};
            for (const [op, c] of Object.entries(prev)) {
                if (c.kind === 'ok' || c.kind === 'mismatch') kept[op] = c;
                else reshareStarted.current.delete(op);
            }
            return kept;
        });
        setRecheck((n) => n + 1);
    }, []);

    // Arriving via a push deep-link: register that capability. Then ALWAYS ask
    // the IdP what else is pending for this identity — opening this screen is
    // the user saying "show me my approvals", and a request whose push never
    // arrived would otherwise be invisible here until it expired.
    useEffect(() => {
        if (params.vault_op) remember(params.vault_op);
        void discover();
    }, [params.vault_op, remember, discover]);

    // Tick so the expiry countdown stays live.
    useEffect(() => {
        const id = setInterval(() => setNow(Date.now()), 1000);
        return () => clearInterval(id);
    }, []);

    // Pull-to-refresh discovers too, so a user who was never pushed can simply
    // pull down to find the request.
    const onRefresh = useCallback(async () => {
        setRefreshing(true);
        recheckReshares();
        await discover();
        setRefreshing(false);
    }, [discover, recheckReshares]);

    const approve = useCallback(
        async (req: VaultApprovalRequest) => {
            const credential = resolveApprovalCredential(req);
            if (!credential) {
                Alert.alert(
                    t('vaultApprovals.wrongDeviceTitle'),
                    t('vaultApprovals.wrongDeviceBody', { detail: describeApprovalMismatch(req) }),
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
            // Strong on Android: the time-bound AUTH_BIOMETRIC_STRONG signing
            // key needs it for the signature that follows (freshBiometric).
            const approved = await freshBiometric(t('vaultApprovals.biometricPrompt'), t('common.cancel'));
            if (!approved) return;

            setApprovingOp(req.vault_op);
            try {
                await approveVaultApproval(req, credential);
                // Audit trail: a one-shot, operation-bound authentication.
                useServiceSessionsStore.getState().record({
                    serviceKey: 'privasys-enclave-vault',
                    displayName: t('vaultApprovals.enclaveVault'),
                    kind: 'approval',
                    identity: 'privasys-id',
                    rpId: req.options.publicKey.rpId ?? 'privasys.id',
                    origin: 'privasys.id',
                    channel: 'push',
                    startedAt: Date.now(),
                    oneShot: true,
                    detail:
                        req.summary.operation === 'promote'
                            ? t('vaultApprovals.detailPromote', { handle: req.summary.handle })
                            : req.summary.operation === 'export'
                              ? t('vaultApprovals.detailExport', { handle: req.summary.handle })
                              : t('vaultApprovals.detailOther', { handle: req.summary.handle })
                });
                // Approved: the request drops off the pending list, which is the
                // confirmation. No success popup — the biometric prompt was the
                // deliberate action, and the terminal continues on its own.
                forget(req.vault_op);
            } catch (e: any) {
                Alert.alert(
                    t('vaultApprovals.approvalFailedTitle'),
                    e?.message ?? t('vaultApprovals.approvalFailedBody')
                );
            } finally {
                setApprovingOp(null);
            }
        },
        [forget],
    );

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('vaultApprovals.title')} />
            <ScrollView
                contentContainerStyle={styles.content}
                refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={p.green} />}
            >
                <Text style={styles.subtitle}>{t('vaultApprovals.subtitle')}</Text>

                {batchIds.map((batchId) => (
                    <Pressable
                        key={batchId}
                        style={[styles.card, styles.batchRow]}
                        onPress={() => router.push({ pathname: '/vault-approvals', params: { batch_id: batchId } })}
                    >
                        <RNView style={styles.cardIcon}>
                            <Ionicons name="list" size={16} color={p.infoText} />
                        </RNView>
                        <RNView style={styles.batchRowText}>
                            <Text style={styles.cardTitle}>{t('vaultApprovals.batchWaitingTitle')}</Text>
                            <Text style={styles.label}>{t('vaultApprovals.batchWaitingHint')}</Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color={p.infoText} />
                    </Pressable>
                ))}

                {loading && pending.length === 0 ? (
                    <ActivityIndicator style={styles.spinner} color={p.green} />
                ) : pending.length === 0 && batchIds.length > 0 ? null : pending.length === 0 ? (
                    <RNView style={styles.emptyCard}>
                        <RNView style={styles.emptyIcon}>
                            <Ionicons name="checkmark-circle" size={30} color={p.green} />
                        </RNView>
                        <Text style={styles.emptyTitle}>{t('vaultApprovals.emptyTitle')}</Text>
                        <Text style={styles.emptyBody}>{t('vaultApprovals.emptyBody')}</Text>
                    </RNView>
                ) : (
                    pending.map((req) => {
                        const highlighted = params.vault_op === req.vault_op;
                        const busy = approvingOp === req.vault_op;
                        const remaining = formatRemaining(req.expires_at, now, t);
                        const urgent = req.expires_at - now / 1000 < 60;
                        const s = req.summary;
                        const subject = s.app_name || shortHandle(s.handle);
                        // An app's own policy: its handle is a namespace, not a
                        // key, and its digest is the document's, not a measurement.
                        const isPolicy = s.operation === 'app-policy';
                        // A key renewal is approvable only once checked: its
                        // target build is a published release and is what the
                        // approval binds.
                        const isReshare = s.operation === 'reshare';
                        const reshare = isReshare ? reshares[req.vault_op] ?? { kind: 'checking' as const } : undefined;
                        // An approval on binding v2 is approvable only once
                        // what it shows is what it signs, for vaults on a
                        // published release.
                        // An operation that exists only on v2 and carries no
                        // binding is refused, never shown as an unchecked v1
                        // card. A v1 card that says what it binds is recomputed.
                        const v2: V2Check | undefined = isV2(s)
                            ? v2Checks[req.vault_op] ?? { kind: 'checking' as const }
                            : requiresV2(s.operation) || !checkV1(req.vault_op, s, computeVaultOp)
                              ? { kind: 'mismatch' as const }
                              : undefined;
                        const isKeyRules = s.operation === 'update_policy' || s.operation === 'update_policy_from';
                        const isKeyCreate = s.operation === 'create';
                        const isKeyDelete = s.operation === 'delete';
                        const isOldKeyDelete = s.operation === 'delete_after';
                        const canApprove = !busy && (!reshare || reshare.kind === 'ok') && (!v2 || v2.kind === 'ok');
                        return (
                            <RNView key={req.vault_op} style={[styles.card, highlighted && styles.cardHighlighted]}>
                                <RNView style={styles.cardHeader}>
                                    <RNView style={styles.cardTitleWrap}>
                                        <RNView style={styles.cardIcon}>
                                            <Ionicons name="key" size={16} color={p.infoText} />
                                        </RNView>
                                        <Text style={styles.cardTitle}>
                                            {s.operation === 'promote'
                                                ? t('vaultApprovals.approveNewVersion')
                                                : s.operation === 'export'
                                                  ? t('vaultApprovals.approveKeyExport')
                                                  : isPolicy
                                                    ? t('vaultApprovals.approvePolicy')
                                                    : isReshare
                                                      ? t('vaultApprovals.approveReshare')
                                                      : isKeyRules
                                                        ? t('vaultApprovals.approveKeyRules')
                                                        : isKeyCreate
                                                          ? t('vaultApprovals.approveKeyCreate')
                                                        : isKeyDelete
                                                          ? t('vaultApprovals.approveKeyDelete')
                                                          : isOldKeyDelete
                                                            ? t('vaultApprovals.approveOldKeyDelete')
                                                            : t('vaultApprovals.approveOperation')}
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
                                            ? t('vaultApprovals.explainPromoteApp')
                                            : t('vaultApprovals.explainPromoteEnclave')
                                        : s.operation === 'export'
                                          ? t('vaultApprovals.explainExport')
                                          : isPolicy
                                            ? t('vaultApprovals.explainPolicy')
                                            : isReshare
                                              ? t('vaultApprovals.explainReshare')
                                              : isKeyRules
                                                ? t('vaultApprovals.explainKeyRules')
                                                : isKeyCreate
                                                  ? t('vaultApprovals.explainKeyCreate')
                                                : isKeyDelete
                                                  ? t('vaultApprovals.explainKeyDelete')
                                                  : isOldKeyDelete
                                                    ? t('vaultApprovals.explainOldKeyDelete')
                                                    : t('vaultApprovals.explainOther')}
                                </Text>

                                {/* The target vault build, as its published
                                    release; anything else is said plainly and
                                    leaves only Decline. */}
                                {reshare?.kind === 'ok' ? (
                                    <>
                                        <ReleaseLinkRow
                                            icon="shield-checkmark-outline"
                                            label={t('vaultApprovals.vaultRelease')}
                                            value={t('vaultApprovals.vaultReleaseName', { version: reshare.release.version })}
                                            url={reshare.release.url}
                                        />
                                        <RNView style={styles.row}>
                                            <Text style={styles.label}>{t('vaultApprovals.newVaults')}</Text>
                                            <Text style={styles.value}>
                                                {t('vaultApprovals.reshareQuorum', {
                                                    threshold: reshare.threshold,
                                                    vaults: reshare.vaults,
                                                })}
                                            </Text>
                                        </RNView>
                                    </>
                                ) :reshare?.kind === 'checking' ? (
                                    <RNView style={styles.row}>
                                        <Text style={styles.label}>{t('vaultApprovals.vaultRelease')}</Text>
                                        <ActivityIndicator size="small" color={p.infoText} />
                                    </RNView>
                                ) : reshare ? (
                                    <RNView style={styles.warnBox} testID="vault-reshare-refused">
                                        <Text style={styles.warnText}>
                                            {reshare.kind === 'mismatch'
                                                ? t('vaultApprovals.reshareMismatch')
                                                : reshare.kind === 'unpublished'
                                                  ? t('vaultApprovals.reshareUnpublished')
                                                  : t('vaultApprovals.reshareUnreachable')}
                                        </Text>
                                        {reshare.kind === 'unpublished' ? (
                                            <Text style={styles.warnMono} selectable>
                                                {reshare.mrenclave}
                                            </Text>
                                        ) : null}
                                    </RNView>
                                ) : null}

                                {/* The vaults this approval is for, as their
                                    published release. */}
                                {v2?.kind === 'ok' ? (
                                    <ReleaseLinkRow
                                        icon="shield-checkmark-outline"
                                        label={t('vaultApprovals.vaultRelease')}
                                        value={t('vaultApprovals.vaultReleaseName', { version: v2.release.version })}
                                        url={v2.release.url}
                                    />
                                ) : null}
                                {/* Which platform those vaults are on: a test
                                    vault and a production one may run the
                                    same release. */}
                                {v2?.kind === 'ok' ? (
                                    <RNView style={styles.row} testID="vault-v2-platform">
                                        <Text style={styles.label}>{t('vaultApprovals.vaultPlatform')}</Text>
                                        <Text style={styles.value}>
                                            {v2.platform.kind === 'default'
                                                ? t('vaultApprovals.platformProduction')
                                                : v2.platform.kind === 'named'
                                                  ? v2.platform.domain
                                                  : t('vaultApprovals.platformUnknown')}
                                        </Text>
                                    </RNView>
                                ) : v2?.kind === 'checking' ? (
                                    <RNView style={styles.row}>
                                        <Text style={styles.label}>{t('vaultApprovals.vaultRelease')}</Text>
                                        <ActivityIndicator size="small" color={p.infoText} />
                                    </RNView>
                                ) : v2 ? (
                                    <RNView style={styles.warnBox} testID="vault-v2-refused">
                                        <Text style={styles.warnText}>
                                            {v2.kind === 'mismatch'
                                                ? t('vaultApprovals.reshareMismatch')
                                                : v2.kind === 'unpublished'
                                                  ? t('vaultApprovals.vaultsUnpublished')
                                                  : t('vaultApprovals.reshareUnreachable')}
                                        </Text>
                                        {v2.kind === 'unpublished' ? (
                                            <Text style={styles.warnMono} selectable>
                                                {v2.build}
                                            </Text>
                                        ) : null}
                                    </RNView>
                                ) : null}

                                {/* The delete of an old key: the key that
                                    replaces it, which the delete waits for. */}
                                {v2?.kind === 'ok' && v2.successor ? (
                                    <RNView style={styles.row} testID="vault-v2-successor">
                                        <Text style={styles.label}>{t('vaultApprovals.replacedBy')}</Text>
                                        <Text style={styles.value}>{shortKeyName(v2.successor)}</Text>
                                    </RNView>
                                ) : null}

                                {/* A change to a key's rules: the rules it
                                    installs, which are what the approval binds. */}
                                {/* What changes, when the approval binds the
                                    rules in force too; then what the new rules
                                    say, in plain facts. */}
                                {v2?.kind === 'ok' && v2.newPolicy !== undefined && v2.currentPolicy !== undefined ? (
                                    <PolicyChangeRows current={v2.currentPolicy} next={v2.newPolicy} t={t} styles={styles} />
                                ) : null}
                                {v2?.kind === 'ok' && v2.newPolicy !== undefined ? (
                                    <PolicyFactRows policy={v2.newPolicy} t={t} styles={styles} />
                                ) : null}
                                {(isKeyRules || isKeyCreate) && v2?.kind === 'ok' && v2.newPolicy !== undefined ? (
                                    <RNView style={styles.summaryBox}>
                                        <Text style={styles.summaryLabel}>{t('vaultApprovals.fullRules')}</Text>
                                        <ScrollView style={styles.rulesScroll} nestedScrollEnabled>
                                            <Text style={styles.rulesText} selectable>
                                                {JSON.stringify(v2.newPolicy, null, 2)}
                                            </Text>
                                        </ScrollView>
                                    </RNView>
                                ) : null}

                                {s.summary ? (
                                    <RNView style={styles.summaryBox}>
                                        <Text style={styles.summaryLabel}>
                                            {isPolicy ? t('vaultApprovals.policyContents') : t('vaultApprovals.operationContents')}
                                        </Text>
                                        <Text style={styles.summaryText}>{s.summary}</Text>
                                    </RNView>
                                ) : null}

                                {s.version && !isPolicy ? (
                                    <RNView style={styles.row}>
                                        <Text style={styles.label}>{t('vaultApprovals.version')}</Text>
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
                                                    label={t('vaultApprovals.publishedRelease')}
                                                    value={relLabel ?? t('serviceDetail.view')}
                                                    url={rel.url}
                                                />
                                            ) : null}
                                            {prov.previous?.compare_url ? (
                                                <ReleaseLinkRow
                                                    icon="git-compare-outline"
                                                    label={t('vaultApprovals.codeChanges')}
                                                    value={
                                                        prov.previous.label && relLabel
                                                            ? `${prov.previous.label} → ${relLabel}`
                                                            : t('vaultApprovals.viewDiff')
                                                    }
                                                    url={prov.previous.compare_url}
                                                />
                                            ) : null}
                                        </>
                                    );
                                })()}
                                {s.key_type && !isPolicy ? (
                                    <RNView style={styles.row}>
                                        <Text style={styles.label}>{t('vaultApprovals.keyType')}</Text>
                                        <Text style={styles.value}>{s.key_type}</Text>
                                    </RNView>
                                ) : null}
                                {!isPolicy ? (
                                    <RNView style={styles.row}>
                                        <Text style={styles.label}>{t('vaultApprovals.appKey')}</Text>
                                        <Text style={styles.value} numberOfLines={1} ellipsizeMode="middle">
                                            {shortHandle(s.handle)}
                                        </Text>
                                    </RNView>
                                ) : null}
                                {typeof s.policy_version === 'number' ? (
                                    <RNView style={styles.row}>
                                        <Text style={styles.label}>{t('vaultApprovals.policyVersion')}</Text>
                                        <Text style={styles.value}>{s.policy_version}</Text>
                                    </RNView>
                                ) : null}
                                {/* A renewal's digest is its resharing context, not
                                    a measurement: the release row above says
                                    what it binds. */}
                                {/* The delete of an old key binds the key that
                                    replaces it, which the row above names. */}
                                {/* A v1 rules change binds its own name there, not a build. */}
                                {s.measurement && !isReshare && !isOldKeyDelete && s.operation !== 'policy-update' ? (
                                    <RNView style={styles.row}>
                                        <Text style={styles.label}>
                                            {isPolicy
                                                ? t('vaultApprovals.policyDocument')
                                                : isKeyRules || isKeyCreate
                                                  ? t('vaultApprovals.rulesFingerprint')
                                                  : t('vaultApprovals.newMeasurement')}
                                        </Text>
                                        <Text style={styles.mono}>{shortHex(s.measurement, t)}</Text>
                                    </RNView>
                                ) : null}
                                <RNView style={[task.actions, styles.cardActions]}>
                                    <Pressable
                                        style={[task.declineButton, busy && task.buttonIdle]}
                                        disabled={busy}
                                        onPress={() => {
                                            decline(req.vault_op);
                                            notify(t('appForm.sentAs.decline'));
                                        }}
                                        accessibilityRole="button"
                                        testID="vault-approval-decline"
                                    >
                                        <Text style={task.declineButtonText}>{t('appForm.action.decline')}</Text>
                                    </Pressable>
                                    <Pressable
                                        style={[task.affirmButton, styles.affirmRow, !canApprove && task.buttonIdle]}
                                        disabled={!canApprove}
                                        onPress={() => {
                                            if (canApprove) void approve(req);
                                        }}
                                        accessibilityRole="button"
                                        accessibilityState={{ disabled: !canApprove }}
                                        testID="vault-approval-approve"
                                    >
                                        {busy ? (
                                            <ActivityIndicator color={p.onGreen} />
                                        ) : (
                                            <>
                                                <Ionicons name="finger-print" size={18} color={p.onGreen} />
                                                <Text style={task.affirmButtonText}>{t('attestation.approve')}</Text>
                                            </>
                                        )}
                                    </Pressable>
                                </RNView>
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
    batchRow: { flexDirection: 'row', alignItems: 'center', gap: 10 },
    batchRowText: { flex: 1, gap: 2 },
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
    row: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8, gap: 12 },
    label: { fontSize: 13, color: p.textSecondary },
    value: { fontSize: 14, fontWeight: '600', color: p.textPrimary, flexShrink: 1, textAlign: 'right' },
    mono: { fontSize: 12, color: p.textSecondary, fontFamily: 'monospace', flexShrink: 1, textAlign: 'right' },
    summaryBox: { backgroundColor: p.infoBg, borderRadius: 10, padding: 12, marginBottom: 12, gap: 4 },
    summaryLabel: { fontSize: 12, fontWeight: '600', color: p.infoText },
    summaryText: { fontSize: 14, color: p.textPrimary, lineHeight: 20 },
    cardActions: { marginTop: 8 },
    warnBox: { backgroundColor: p.dangerBg, borderRadius: 10, padding: 12, marginBottom: 12, gap: 6 },
    warnText: { fontSize: 14, lineHeight: 20, color: p.dangerText, fontWeight: '600' },
    warnMono: { fontSize: 11, color: p.dangerText, fontFamily: 'monospace' },
    // The rules a policy update installs: the preview text of the report
    // screen (connect.tsx previewText), kept to a height the card can hold.
    rulesScroll: { maxHeight: 220 },
    rulesText: { fontSize: 11, fontFamily: MONO, color: p.textPrimary, lineHeight: 16 },
    affirmRow: { flexDirection: 'row', justifyContent: 'center', gap: 8 },
});
