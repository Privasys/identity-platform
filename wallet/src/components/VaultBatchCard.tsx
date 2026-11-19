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
    resolveApprovalCredential,
} from '@/services/vault-approval-api';
import {
    describeVaultHandle,
    reachedEndOfList,
    vaultBatchRouteName,
    type VaultBatchKeyKind,
    type VerifiedVaultBatch,
    type VerifiedVaultBatchEntry,
} from '@/services/vault-approval-batch';
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
    const [names, setNames] = useState<Record<string, string>>({});
    const [readToEnd, setReadToEnd] = useState(false);
    const [busy, setBusy] = useState(false);
    const [now, setNow] = useState(() => Date.now());
    const layout = useRef({ offsetY: 0, viewportHeight: 0, contentHeight: 0 });

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
            void lookupVaultBatchAppName(id).then((name) => {
                if (!cancelled && name) setNames((prev) => ({ ...prev, [id]: name }));
            });
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
        const left = Math.max(0, Math.round(exp - now / 1000));
        const expired = left === 0;
        const canApprove = readToEnd && !expired && !busy;
        return (
            <>
                <Text style={styles.fromText}>{t('vaultApprovals.batchTitle', { count: entries.length })}</Text>

                <RNView style={[styles.card, expired && styles.cardDimmed]} testID="vault-batch-card">
                    <RNView style={styles.line}>
                        <Text style={styles.lineLabel}>{t('vaultApprovals.batchLabelCaption')}</Text>
                        <Text style={styles.lineValue}>{label}</Text>
                    </RNView>
                    <RNView style={styles.divider} />
                    <RNView style={styles.lines}>
                        {entries.map((entry) => (
                            <EntryLine key={`${entry.operation} ${entry.handle}`} entry={entry} names={names} styles={styles} />
                        ))}
                    </RNView>
                    <RNView style={styles.divider} />
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
                                onPress={leave}
                                accessibilityRole="button"
                            >
                                <Text style={styles.declineButtonText}>{t('common.cancel')}</Text>
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

/** One entry: the kind of key over the app (or host) it belongs to, and the
 *  id and digest the signature binds, so the name never stands alone. */
function EntryLine({
    entry,
    names,
    styles,
}: {
    entry: VerifiedVaultBatchEntry;
    names: Record<string, string>;
    styles: ReturnType<typeof taskStyles>;
}) {
    const { t } = useTranslation();
    const subject = describeVaultHandle(entry.handle);
    const id = subject.appId ?? subject.enclaveId;
    const name =
        subject.kind === 'host'
            ? t('vaultApprovals.batchHostSubject')
            : subject.appId
              ? (names[subject.appId] ?? t('vaultApprovals.batchUnknownApp'))
              : entry.handle;
    const digestLabel = subject.kind === 'policy' ? t('vaultApprovals.policyDocument') : t('vaultApprovals.newMeasurement');
    return (
        <RNView style={styles.line} testID="vault-batch-entry">
            <Text style={styles.lineLabel}>{t(KIND_KEY[subject.kind])}</Text>
            <Text style={styles.lineValue}>{name}</Text>
            {id ? <Text style={styles.meta}>{shortId(id)}</Text> : null}
            <Text style={styles.meta}>{`${digestLabel} ${shortDigest(entry.measurementDigest)}`}</Text>
        </RNView>
    );
}
