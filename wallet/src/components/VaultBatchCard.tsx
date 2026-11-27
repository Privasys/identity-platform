// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One approval for a list of vault operations.
 *
 * One tap here carries the weight of many, so the card is built to make it as
 * deliberate: nothing shows until the list has been verified against what the
 * passkey will sign (services/vault-approval-batch), every entry has its own
 * line in the card, and Approve stays off until the holder has reached the end.
 *
 * It is a task like the app's approval and form screens and wears their look
 * (components/task-styles): the card holds what is being decided, and the
 * answers follow it in the same scroll, so they can never show without it. A
 * list with nothing to show is refused, never offered.
 *
 * What a line says comes from the signed handle, and the app's name from the
 * control plane by the id in that handle. The label is the one thing written
 * by whoever began the batch, so it is presented as their description.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { router } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
    ActivityIndicator,
    Alert,
    Pressable,
    ScrollView,
    StyleSheet,
    View as RNView,
    type NativeScrollEvent,
    type NativeSyntheticEvent,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { SubPageHeader } from '@/components/SubPageHeader';
import { taskStyles } from '@/components/task-styles';
import { Text, usePalette } from '@/components/Themed';
import { freshBiometric } from '@/services/approval-answer';
import {
    approveVaultBatch,
    describeApprovalMismatch,
    fetchVaultBatch,
    lookupVaultBatchAppName,
    lookupVaultBatchHost,
    lookupVaultBatchVersion,
    resolveApprovalCredential,
    type VaultBatchHost,
} from '@/services/vault-approval-api';
import {
    describeVaultHandle,
    groupVaultBatch,
    reachedEndOfList,
    vaultBatchRouteName,
    type VaultBatchGroup,
    type VaultBatchKeyKind,
    type VerifiedVaultBatch,
} from '@/services/vault-approval-batch';
import { refusedOnRelease } from '@/services/vault-approval-v2';
import { vaultReleaseFor, type VaultRelease } from '@/services/vault-reshare';
import { billingPlatform, type BillingPlatform } from '@/services/platforms';
import { sha256 } from '@noble/hashes/sha2.js';
import { notify } from '@/stores/notice';
import { useServiceSessionsStore } from '@/stores/service-sessions';
import { useVaultApprovalsStore } from '@/stores/vaultApprovals';
import { useActiveRoute } from '@/utils/active-route';

type Phase =
    | { kind: 'loading' }
    | { kind: 'failed' }
    | { kind: 'gone' }
    | { kind: 'refused' }
    | { kind: 'ready'; batch: VerifiedVaultBatch };

const KIND_KEY: Record<VaultBatchKeyKind, string> = {
    storage: 'vaultApprovals.batchKindStorage',
    registry: 'vaultApprovals.batchKindRegistry',
    host: 'vaultApprovals.batchKindHost',
    session: 'vaultApprovals.batchKindSession',
    data: 'vaultApprovals.batchKindData',
    policy: 'vaultApprovals.batchKindPolicy',
    other: 'vaultApprovals.batchKindOther',
};

const shortId = (id: string) => `${id.slice(0, 8)}…${id.slice(-4)}`;
const shortDigest = (d: string) => `${d.slice(0, 10)}…${d.slice(-6)}`;

export function VaultBatchCard({ batchId }: { batchId: string }) {
    useActiveRoute(vaultBatchRouteName(batchId));
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => taskStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const forgetBatch = useVaultApprovalsStore((s) => s.forgetBatch);

    const [phase, setPhase] = useState<Phase>({ kind: 'loading' });
    // An app's name by its id: a string once the control plane confirms it,
    // null when it could not, absent while asking.
    const [names, setNames] = useState<Record<string, string | null>>({});
    // A host by its enclave id, and an app's version label by its app id: the
    // control plane's answers, shown when they come and never waited for.
    const [hosts, setHosts] = useState<Record<string, VaultBatchHost | null>>({});
    const [versions, setVersions] = useState<Record<string, string | null>>({});
    // A v2 batch names its vaults: their build, as a published Enclave Vault
    // release, before Approve is offered. Absent for a batch that names none.
    const [release, setRelease] = useState<
        | { kind: 'checking' }
        | { kind: 'ok'; release: VaultRelease }
        | { kind: 'unpublished' }
        | { kind: 'unreachable' }
        | { kind: 'mismatch' }
        | null
    >(null);
    // Which platform those vaults are on: a test vault and a production one
    // may run the same release.
    const [platform, setPlatform] = useState<BillingPlatform | null>(null);
    const billingKey = phase.kind === 'ready' && phase.batch.billingIds ? phase.batch.billingIds.join(',') : null;
    useEffect(() => {
        if (billingKey === null) {
            setPlatform(null);
            return;
        }
        let cancelled = false;
        const sha256Hex = (text: string) =>
            Array.from(sha256(new TextEncoder().encode(text)), (b) => b.toString(16).padStart(2, '0')).join('');
        void billingPlatform(billingKey === '' ? [] : billingKey.split(','), sha256Hex).then((found) => {
            if (!cancelled) setPlatform(found);
        });
        return () => {
            cancelled = true;
        };
    }, [billingKey]);
    const [readToEnd, setReadToEnd] = useState(false);
    const [busy, setBusy] = useState(false);
    const [now, setNow] = useState(() => Date.now());
    const layout = useRef({ offsetY: 0, viewportHeight: 0, contentHeight: 0 });

    const builds = phase.kind === 'ready' ? phase.batch.builds : undefined;
    const buildsKey = builds ? builds.join(',') : null;
    // The batch's operations, for the rule a release puts on them.
    const opsKey = phase.kind === 'ready' ? [...new Set(phase.batch.entries.map((e) => e.operation))].sort().join(',') : '';
    useEffect(() => {
        if (buildsKey === null) {
            setRelease(null);
            return;
        }
        const list = buildsKey === '' ? [] : buildsKey.split(',');
        if (list.length !== 1) {
            setRelease({ kind: 'unpublished' });
            return;
        }
        let cancelled = false;
        setRelease({ kind: 'checking' });
        vaultReleaseFor(list[0]).then(
            (r) => {
                if (cancelled) return;
                if (!r) setRelease({ kind: 'unpublished' });
                else if (opsKey.split(',').some((op) => refusedOnRelease(op, r.version))) setRelease({ kind: 'mismatch' });
                else setRelease({ kind: 'ok', release: r });
            },
            () => {
                if (!cancelled) setRelease({ kind: 'unreachable' });
            },
        );
        return () => {
            cancelled = true;
        };
    }, [buildsKey, opsKey]);

    const load = useCallback(async () => {
        setPhase({ kind: 'loading' });
        try {
            const found = await fetchVaultBatch(batchId);
            if (found.kind === 'ok') {
                // Verified, but a list with nothing in it has nothing to show,
                // and an approval with nothing shown is not offered.
                setPhase(found.batch.entries.length > 0 ? { kind: 'ready', batch: found.batch } : { kind: 'refused' });
                return;
            }
            if (found.kind === 'gone') forgetBatch(batchId);
            setPhase({ kind: found.kind });
        } catch {
            setPhase({ kind: 'failed' });
        }
    }, [batchId, forgetBatch]);

    useEffect(() => {
        void load();
    }, [load]);

    const batch = phase.kind === 'ready' ? phase.batch : null;

    useEffect(() => {
        if (!batch) return;
        let cancelled = false;
        const ids = new Set(batch.entries.map((e) => describeVaultHandle(e.handle).appId).filter(Boolean));
        for (const id of ids as Set<string>) {
            void lookupVaultBatchAppName(id)
                .catch(() => null)
                .then((name) => {
                    if (!cancelled) setNames((prev) => ({ ...prev, [id]: name || null }));
                });
        }
        for (const group of groupVaultBatch(batch.entries)) {
            const id = group.id;
            if (!id) continue;
            if (group.subject === 'host') {
                void lookupVaultBatchHost(id)
                    .catch(() => null)
                    .then((host) => {
                        if (!cancelled) setHosts((prev) => ({ ...prev, [id]: host }));
                    });
            } else if (group.subject === 'app' && group.versionIdHint) {
                void lookupVaultBatchVersion(id, group.versionIdHint).then((prov) => {
                    const label = prov?.workload_release?.label || prov?.version?.label || null;
                    if (!cancelled) setVersions((prev) => ({ ...prev, [id]: label }));
                });
            }
        }
        return () => {
            cancelled = true;
        };
    }, [batch]);

    useEffect(() => {
        const id = setInterval(() => setNow(Date.now()), 1000);
        return () => clearInterval(id);
    }, []);

    const measure = useCallback((next: Partial<typeof layout.current>) => {
        layout.current = { ...layout.current, ...next };
        if (reachedEndOfList(layout.current)) setReadToEnd(true);
    }, []);

    const onScroll = useCallback(
        (e: NativeSyntheticEvent<NativeScrollEvent>) => {
            const { contentOffset, contentSize, layoutMeasurement } = e.nativeEvent;
            measure({
                offsetY: contentOffset.y,
                contentHeight: contentSize.height,
                viewportHeight: layoutMeasurement.height,
            });
        },
        [measure],
    );

    const leave = useCallback(() => {
        if (router.canGoBack()) router.back();
        else router.replace('/access');
    }, []);

    // Declining hides the batch for good, tells the identity provider, and
    // leaves: closing alone left it waiting on the Access screen.
    const declineBatch = useVaultApprovalsStore((s) => s.declineBatch);
    const decline = useCallback(() => {
        declineBatch(batchId);
        notify(t('appForm.sentAs.decline'));
        leave();
    }, [batchId, declineBatch, leave, t]);

    const approve = useCallback(async () => {
        if (!batch || busy) return;
        const credential = resolveApprovalCredential(batch);
        if (!credential) {
            Alert.alert(
                t('vaultApprovals.wrongDeviceTitle'),
                t('vaultApprovals.wrongDeviceBody', { detail: describeApprovalMismatch(batch) }),
            );
            return;
        }
        if (!(await freshBiometric(t('vaultApprovals.biometricPrompt'), t('common.cancel')))) return;
        setBusy(true);
        try {
            await approveVaultBatch(batch, credential);
            useServiceSessionsStore.getState().record({
                serviceKey: 'privasys-enclave-vault',
                displayName: t('vaultApprovals.enclaveVault'),
                kind: 'approval',
                identity: 'privasys-id',
                rpId: batch.options.publicKey.rpId ?? 'privasys.id',
                origin: 'privasys.id',
                channel: 'push',
                startedAt: Date.now(),
                oneShot: true,
                detail: t('vaultApprovals.batchDetail', { count: batch.entries.length, label: batch.label }),
            });
            forgetBatch(batch.batchId);
            // As the app's approval does: the strip says so, and the screen goes.
            notify(t('vaultApprovals.batchDoneTitle'), t('vaultApprovals.batchDoneBody'));
            leave();
        } catch (e: any) {
            Alert.alert(t('vaultApprovals.approvalFailedTitle'), e?.message ?? t('vaultApprovals.approvalFailedBody'));
        } finally {
            setBusy(false);
        }
    }, [batch, busy, forgetBatch, leave, t]);

    const body = (() => {
        if (phase.kind === 'loading') {
            return <ActivityIndicator style={styles.spinner} color={p.textSecondary} />;
        }
        if (phase.kind === 'refused' || phase.kind === 'gone') {
            const refused = phase.kind === 'refused';
            return (
                <>
                    <RNView style={styles.refused} testID={`vault-batch-${phase.kind}`}>
                        <Ionicons
                            name={refused ? 'warning-outline' : 'checkmark-circle-outline'}
                            size={32}
                            color={refused ? p.danger : p.textSecondary}
                        />
                        <Text style={styles.fromText}>
                            {t(refused ? 'vaultApprovals.batchRefusedTitle' : 'vaultApprovals.batchGoneTitle')}
                        </Text>
                        <Text style={refused ? styles.error : styles.closed}>
                            {t(refused ? 'vaultApprovals.batchRefusedBody' : 'vaultApprovals.batchGoneBody')}
                        </Text>
                    </RNView>
                    <Pressable style={styles.doneButton} onPress={leave} accessibilityRole="button">
                        <Text style={styles.doneButtonText}>{t('common.done')}</Text>
                    </Pressable>
                </>
            );
        }
        if (phase.kind === 'failed') {
            return (
                <>
                    <RNView style={styles.refused} testID="vault-batch-failed">
                        <Ionicons name="cloud-offline-outline" size={32} color={p.textSecondary} />
                        <Text style={styles.fromText}>{t('vaultApprovals.batchFailedTitle')}</Text>
                        <Text style={styles.closed}>{t('vaultApprovals.batchFailedBody')}</Text>
                    </RNView>
                    <RNView style={styles.actions}>
                        <Pressable style={styles.declineButton} onPress={leave} accessibilityRole="button">
                            <Text style={styles.declineButtonText}>{t('common.close')}</Text>
                        </Pressable>
                        <Pressable style={styles.retryButton} onPress={() => void load()} accessibilityRole="button">
                            <Text style={styles.doneButtonText}>{t('common.retry')}</Text>
                        </Pressable>
                    </RNView>
                </>
            );
        }

        const { label, entries, exp } = phase.batch;
        const groups = groupVaultBatch(entries);
        const apps = groups.filter((g) => g.subject === 'app').length;
        const left = Math.max(0, Math.round(exp - now / 1000));
        const expired = left === 0;
        // Not while a name is still being looked up: what is approved is shown
        // in full first. A name that could not be confirmed is flagged instead.
        const named = groups.every((g) => g.subject !== 'app' || !g.id || g.id in names);
        const releaseOk = release === null || release.kind === 'ok';
        const canApprove = readToEnd && named && releaseOk && !expired && !busy;
        return (
            <>
                <RNView style={styles.from}>
                    <Text style={styles.fromText}>{t('vaultApprovals.batchTitle', { count: entries.length })}</Text>
                    {apps > 0 ? <Text style={styles.meta}>{t('vaultApprovals.batchAppCount', { count: apps })}</Text> : null}
                </RNView>

                <RNView style={[styles.card, expired && styles.cardDimmed]} testID="vault-batch-card">
                    <RNView style={styles.line}>
                        <Text style={styles.lineLabel}>{t('vaultApprovals.batchLabelCaption')}</Text>
                        <Text style={styles.lineValue}>{label}</Text>
                    </RNView>
                    <RNView style={styles.line}>
                        <Text style={styles.lineLabel}>{t('vaultApprovals.batchWhatChanges')}</Text>
                        <Text style={styles.meta}>{t('vaultApprovals.batchWhatChangesBody')}</Text>
                    </RNView>
                    <RNView style={styles.divider} />
                    <RNView style={extra.groups}>
                        {groups.map((group) => (
                            <GroupBlock
                                key={group.key}
                                group={group}
                                names={names}
                                host={group.id ? hosts[group.id] : undefined}
                                version={group.id ? versions[group.id] : undefined}
                                styles={styles}
                            />
                        ))}
                    </RNView>
                    <RNView style={styles.divider} />
                    {release?.kind === 'ok' || release?.kind === 'checking' ? (
                        <RNView style={styles.metaRow} testID="vault-batch-release">
                            <Ionicons name="shield-checkmark-outline" size={16} color={p.textSecondary} />
                            <Text style={styles.meta}>
                                {release.kind === 'ok'
                                    ? t('vaultApprovals.vaultReleaseName', { version: release.release.version })
                                    : t('vaultApprovals.vaultRelease')}
                            </Text>
                        </RNView>
                    ) : null}
                    {release?.kind === 'ok' && platform ? (
                        <RNView style={styles.metaRow} testID="vault-batch-platform">
                            <Ionicons name="server-outline" size={16} color={p.textSecondary} />
                            <Text style={styles.meta}>
                                {platform.kind === 'default'
                                    ? t('vaultApprovals.platformProduction')
                                    : platform.kind === 'named'
                                      ? platform.domain
                                      : t('vaultApprovals.platformUnknown')}
                            </Text>
                        </RNView>
                    ) : null}
                    {release && release.kind !== 'ok' && release.kind !== 'checking' ? (
                        <RNView style={styles.metaRow} testID="vault-batch-release-refused">
                            <Ionicons name="warning-outline" size={16} color={p.danger} />
                            <Text style={[styles.meta, { color: p.danger }]}>
                                {release.kind === 'unpublished'
                                    ? t('vaultApprovals.vaultsUnpublished')
                                    : release.kind === 'mismatch'
                                      ? t('vaultApprovals.reshareMismatch')
                                      : t('vaultApprovals.batchReleaseUnreachable')}
                            </Text>
                        </RNView>
                    ) : null}
                    <RNView style={styles.metaRow}>
                        <Ionicons name="finger-print-outline" size={16} color={p.textSecondary} />
                        <Text style={styles.meta}>{t('approval.assurance.device')}</Text>
                    </RNView>
                    <RNView style={styles.metaRow}>
                        <Ionicons name="time-outline" size={16} color={expired ? p.danger : p.textSecondary} />
                        <Text style={[styles.meta, expired && { color: p.danger }]}>
                            {expired
                                ? t('vaultApprovals.expired')
                                : t('approval.timeLeft', {
                                      time: `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`,
                                  })}
                        </Text>
                    </RNView>
                </RNView>

                {expired ? (
                    <Pressable style={styles.doneButton} onPress={leave} accessibilityRole="button">
                        <Text style={styles.doneButtonText}>{t('common.done')}</Text>
                    </Pressable>
                ) : (
                    <>
                        <RNView style={styles.actions}>
                            <Pressable
                                style={[styles.declineButton, busy && styles.buttonIdle]}
                                disabled={busy}
                                onPress={decline}
                                accessibilityRole="button"
                                testID="vault-batch-decline"
                            >
                                <Text style={styles.declineButtonText}>{t('appForm.action.decline')}</Text>
                            </Pressable>
                            <Pressable
                                style={[styles.affirmButton, !canApprove && !busy && styles.buttonIdle]}
                                disabled={!canApprove}
                                onPress={() => void approve()}
                                accessibilityRole="button"
                                accessibilityState={{ disabled: !canApprove, busy }}
                                testID="vault-batch-approve"
                            >
                                {busy ? (
                                    <ActivityIndicator color={p.onGreen} />
                                ) : (
                                    <Text style={styles.affirmButtonText}>{t('appForm.action.approve')}</Text>
                                )}
                            </Pressable>
                        </RNView>
                        {!readToEnd ? <Text style={styles.note}>{t('vaultApprovals.batchScrollHint')}</Text> : null}
                    </>
                )}
            </>
        );
    })();

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('vaultApprovals.title')} />
            <ScrollView
                contentContainerStyle={[styles.body, { paddingBottom: insets.bottom + 32 }]}
                scrollEventThrottle={32}
                onScroll={onScroll}
                onLayout={(e) => measure({ viewportHeight: e.nativeEvent.layout.height })}
                onContentSizeChange={(_, height) => measure({ contentHeight: height })}
                testID="vault-batch-list"
            >
                {body}
            </ScrollView>
        </RNView>
    );
}

/**
 * One app (or the host) and what the approval changes for it. The name is the
 * control plane's, found by the id inside the signed handle; the id stays
 * beside it, and a name that could not be confirmed says so rather than
 * standing in for one. Each line keeps the digest the signature binds.
 */
function GroupBlock({
    group,
    names,
    host,
    version,
    styles,
}: {
    group: VaultBatchGroup;
    names: Record<string, string | null>;
    /** The control plane's answer for a host group; absent while asking. */
    host?: VaultBatchHost | null;
    /** The published version label for an app group; absent while asking. */
    version?: string | null;
    styles: ReturnType<typeof taskStyles>;
}) {
    const { t } = useTranslation();
    const p = usePalette();
    const looked = group.subject === 'app' && group.id ? names[group.id] : undefined;
    const unconfirmed = group.subject === 'app' && looked === null;
    // Where the host is and what it runs now; an app's published version.
    const detail =
        group.subject === 'host'
            ? [host?.region, host?.release].filter(Boolean).join(' · ')
            : group.subject === 'app'
              ? (version ?? '')
              : '';
    const name =
        group.subject === 'host'
            ? (host?.name ?? t('vaultApprovals.batchHostSubject'))
            : group.subject === 'other'
              ? group.entries[0].handle
              : unconfirmed
                ? t('vaultApprovals.batchNameUnconfirmed')
                : (looked ?? '…');
    return (
        <RNView style={styles.line} testID="vault-batch-group">
            <RNView style={extra.groupHead}>
                {unconfirmed ? <Ionicons name="warning-outline" size={15} color={p.warnText} /> : null}
                <Text style={[styles.lineValue, extra.groupName, unconfirmed && { color: p.warnText }]}>{name}</Text>
                {group.id ? <Text style={styles.meta}>{shortId(group.id)}</Text> : null}
            </RNView>
            {detail ? (
                <Text style={styles.meta} testID="vault-batch-group-detail">
                    {detail}
                </Text>
            ) : null}
            {group.entries.map((entry) => {
                const kind = describeVaultHandle(entry.handle).kind;
                const digestLabel =
                    kind === 'policy' ? t('vaultApprovals.policyDocument') : t('vaultApprovals.newMeasurement');
                return (
                    <RNView key={`${entry.operation} ${entry.handle}`} style={extra.op} testID="vault-batch-entry">
                        <Text style={styles.lineLabel}>{t(KIND_KEY[kind])}</Text>
                        <Text style={styles.lineLabel}>
                            {entry.operation === 'delete_after'
                                ? t('vaultApprovals.batchDeleteOld')
                                : entry.operation === 'update_policy'
                                  ? `${t('vaultApprovals.newKeyRules')} ${shortDigest(entry.measurementDigest)}`
                                  : `${digestLabel} ${shortDigest(entry.measurementDigest)}`}
                        </Text>
                    </RNView>
                );
            })}
        </RNView>
    );
}

/** What this card has that the task styles do not: the app groups. */
const extra = StyleSheet.create({
    groups: { gap: 14 },
    groupHead: { flexDirection: 'row', alignItems: 'center', gap: 6 },
    groupName: { flex: 1, fontWeight: '600' },
    op: { flexDirection: 'row', flexWrap: 'wrap', justifyContent: 'space-between', columnGap: 12 },
});
