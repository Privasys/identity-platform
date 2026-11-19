// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One approval for a list of vault operations.
 *
 * One tap here carries the weight of many, so the card is built to make it as
 * deliberate: nothing shows until the list has been verified against what the
 * passkey will sign (services/vault-approval-batch), every entry has its own
 * row, and Approve stays off until the holder has reached the end of the list.
 *
 * What a row says comes from the signed handle, and the app's name from the
 * control plane by the id in that handle. The label is the one thing written by
 * whoever began the batch, so it is presented as their description.
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

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
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
import { useServiceSessionsStore } from '@/stores/service-sessions';
import { useVaultApprovalsStore } from '@/stores/vaultApprovals';
import { useActiveRoute } from '@/utils/active-route';

type Phase =
    | { kind: 'loading' }
    | { kind: 'failed' }
    | { kind: 'gone' }
    | { kind: 'refused' }
    | { kind: 'ready'; batch: VerifiedVaultBatch }
    | { kind: 'done'; count: number };

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

export function VaultBatchCard({ batchId }: { batchId: string }) {
    useActiveRoute(vaultBatchRouteName(batchId));
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
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
                setPhase({ kind: 'ready', batch: found.batch });
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

    const close = useCallback(() => {
        if (router.canGoBack()) router.back();
        else router.replace('/');
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
            setPhase({ kind: 'done', count: batch.entries.length });
        } catch (e: any) {
            Alert.alert(t('vaultApprovals.approvalFailedTitle'), e?.message ?? t('vaultApprovals.approvalFailedBody'));
        } finally {
            setBusy(false);
        }
    }, [batch, busy, forgetBatch, t]);

    if (phase.kind !== 'ready') {
        return (
            <RNView style={styles.screen}>
                <SubPageHeader title={t('vaultApprovals.title')} />
                {phase.kind === 'loading' ? (
                    <ActivityIndicator style={styles.spinner} color={p.green} />
                ) : (
                    <Outcome phase={phase} styles={styles} p={p} onClose={close} onRetry={load} />
                )}
            </RNView>
        );
    }

    const { label, entries, exp } = phase.batch;
    const secondsLeft = Math.max(0, Math.round(exp - now / 1000));
    const expired = secondsLeft <= 0;
    const canApprove = readToEnd && !expired && !busy;
    const remaining = expired
        ? t('vaultApprovals.expired')
        : secondsLeft >= 60
          ? t('vaultApprovals.expiresInMinutes', { minutes: Math.floor(secondsLeft / 60), seconds: secondsLeft % 60 })
          : t('vaultApprovals.expiresInSeconds', { count: secondsLeft });

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('vaultApprovals.title')} />
            <ScrollView
                contentContainerStyle={styles.content}
                scrollEventThrottle={32}
                onScroll={onScroll}
                onLayout={(e) => measure({ viewportHeight: e.nativeEvent.layout.height })}
                onContentSizeChange={(_, height) => measure({ contentHeight: height })}
                testID="vault-batch-list"
            >
                <RNView style={styles.titleRow}>
                    <Text style={styles.title}>{t('vaultApprovals.batchTitle', { count: entries.length })}</Text>
                    <RNView style={[styles.ttlPill, secondsLeft < 60 && styles.ttlPillUrgent]}>
                        <Ionicons name="time-outline" size={12} color={secondsLeft < 60 ? p.warnText : p.infoText} />
                        <Text style={[styles.ttlText, secondsLeft < 60 && styles.ttlTextUrgent]}>{remaining}</Text>
                    </RNView>
                </RNView>

                <RNView style={styles.labelBox}>
                    <Text style={styles.labelCaption}>{t('vaultApprovals.batchLabelCaption')}</Text>
                    <Text style={styles.labelText}>{label}</Text>
                </RNView>

                <RNView style={styles.list}>
                    {entries.map((entry, i) => (
                        <BatchRow
                            key={`${entry.operation} ${entry.handle}`}
                            entry={entry}
                            names={names}
                            last={i === entries.length - 1}
                            styles={styles}
                            p={p}
                        />
                    ))}
                </RNView>
            </ScrollView>

            <RNView style={styles.footer}>
                {!readToEnd ? <Text style={styles.hint}>{t('vaultApprovals.batchScrollHint')}</Text> : null}
                <Pressable
                    style={[styles.approveBtn, !canApprove && styles.approveBtnDisabled]}
                    disabled={!canApprove}
                    onPress={() => void approve()}
                    accessibilityRole="button"
                    accessibilityState={{ disabled: !canApprove, busy }}
                    testID="vault-batch-approve"
                >
                    {busy ? (
                        <ActivityIndicator color={p.onGreen} />
                    ) : (
                        <>
                            <Ionicons name="finger-print" size={18} color={p.onGreen} />
                            <Text style={styles.approveText}>{t('attestation.approve')}</Text>
                        </>
                    )}
                </Pressable>
            </RNView>
        </RNView>
    );
}

function BatchRow({
    entry,
    names,
    last,
    styles,
    p,
}: {
    entry: VerifiedVaultBatchEntry;
    names: Record<string, string>;
    last: boolean;
    styles: ReturnType<typeof makeStyles>;
    p: Palette;
}) {
    const { t } = useTranslation();
    const subject = describeVaultHandle(entry.handle);
    const id = subject.appId ?? subject.enclaveId;
    const title =
        subject.kind === 'host'
            ? t('vaultApprovals.batchHostSubject')
            : subject.appId
              ? (names[subject.appId] ?? t('vaultApprovals.batchUnknownApp'))
              : t(KIND_KEY.other);
    const digest = entry.measurementDigest;
    return (
        <RNView style={[styles.row, !last && styles.rowDivider]}>
            <RNView style={styles.rowIcon}>
                <Ionicons name={subject.kind === 'policy' ? 'document-text' : 'key'} size={15} color={p.infoText} />
            </RNView>
            <RNView style={styles.rowText}>
                <Text style={styles.rowTitle}>{title}</Text>
                <Text style={styles.rowKind}>{t(KIND_KEY[subject.kind])}</Text>
                {/* The id is what the signature binds: it stays beside the name. */}
                <Text style={styles.mono}>{id ? shortId(id) : entry.handle}</Text>
                <Text style={styles.mono}>
                    {subject.kind === 'policy' ? t('vaultApprovals.policyDocument') : t('vaultApprovals.newMeasurement')}
                    {` ${digest.slice(0, 10)}…${digest.slice(-6)}`}
                </Text>
            </RNView>
        </RNView>
    );
}

function Outcome({
    phase,
    styles,
    p,
    onClose,
    onRetry,
}: {
    phase: Exclude<Phase, { kind: 'loading' } | { kind: 'ready' }>;
    styles: ReturnType<typeof makeStyles>;
    p: Palette;
    onClose: () => void;
    onRetry: () => void;
}) {
    const { t } = useTranslation();
    const refused = phase.kind === 'refused';
    const copy = {
        refused: ['vaultApprovals.batchRefusedTitle', 'vaultApprovals.batchRefusedBody'],
        gone: ['vaultApprovals.batchGoneTitle', 'vaultApprovals.batchGoneBody'],
        failed: ['vaultApprovals.batchFailedTitle', 'vaultApprovals.batchFailedBody'],
        done: ['vaultApprovals.batchDoneTitle', 'vaultApprovals.batchDoneBody'],
    }[phase.kind];
    return (
        <RNView style={styles.outcome} testID={`vault-batch-${phase.kind}`}>
            <Ionicons
                name={refused ? 'shield-outline' : phase.kind === 'done' ? 'checkmark-circle' : 'time-outline'}
                size={40}
                color={refused ? p.dangerText : p.infoText}
            />
            <Text style={styles.outcomeTitle}>{t(copy[0])}</Text>
            <Text style={styles.outcomeBody}>{t(copy[1])}</Text>
            {phase.kind === 'failed' ? (
                <Pressable style={styles.approveBtn} onPress={onRetry} accessibilityRole="button">
                    <Text style={styles.approveText}>{t('common.retry')}</Text>
                </Pressable>
            ) : null}
            <Pressable style={styles.closeBtn} onPress={onClose} accessibilityRole="button">
                <Text style={styles.closeText}>{t('common.close')}</Text>
            </Pressable>
        </RNView>
    );
}

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        screen: { flex: 1, backgroundColor: p.screenBg },
        spinner: { marginTop: 40 },
        content: { padding: 16, paddingBottom: 24, gap: 14 },
        titleRow: { flexDirection: 'row', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10 },
        title: { flex: 1, fontSize: 20, fontWeight: '700', color: p.textPrimary },
        ttlPill: {
            flexDirection: 'row',
            alignItems: 'center',
            gap: 4,
            backgroundColor: p.infoBg,
            paddingHorizontal: 8,
            paddingVertical: 3,
            borderRadius: 10,
        },
        ttlPillUrgent: { backgroundColor: p.warnBg },
        ttlText: { fontSize: 12, fontWeight: '600', color: p.infoText },
        ttlTextUrgent: { color: p.warnText },
        labelBox: { backgroundColor: p.infoBg, borderRadius: 10, padding: 12, gap: 4 },
        labelCaption: { fontSize: 12, fontWeight: '600', color: p.infoText },
        labelText: { fontSize: 14, lineHeight: 20, color: p.textPrimary },
        list: { backgroundColor: p.card, borderRadius: 16, paddingHorizontal: 14 },
        row: { flexDirection: 'row', gap: 10, paddingVertical: 12 },
        rowDivider: { borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: p.textSecondary },
        rowIcon: {
            width: 28,
            height: 28,
            borderRadius: 8,
            backgroundColor: p.infoBg,
            alignItems: 'center',
            justifyContent: 'center',
        },
        rowText: { flex: 1, gap: 2 },
        rowTitle: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
        rowKind: { fontSize: 13, color: p.textSecondary },
        mono: { fontSize: 12, color: p.textSecondary, fontFamily: 'monospace' },
        footer: { paddingHorizontal: 16, paddingTop: 10, paddingBottom: 24, gap: 8, backgroundColor: p.screenBg },
        hint: { fontSize: 13, color: p.textSecondary, textAlign: 'center' },
        approveBtn: {
            flexDirection: 'row',
            gap: 8,
            alignSelf: 'stretch',
            backgroundColor: p.green,
            borderRadius: 12,
            paddingVertical: 13,
            alignItems: 'center',
            justifyContent: 'center',
        },
        approveBtnDisabled: { opacity: 0.45 },
        approveText: { color: p.onGreen, fontWeight: '700', fontSize: 15 },
        outcome: { padding: 24, paddingTop: 48, alignItems: 'center', gap: 12 },
        outcomeTitle: { fontSize: 18, fontWeight: '700', color: p.textPrimary, textAlign: 'center' },
        outcomeBody: { fontSize: 14, lineHeight: 20, color: p.textSecondary, textAlign: 'center', marginBottom: 8 },
        closeBtn: { alignSelf: 'stretch', paddingVertical: 13, alignItems: 'center' },
        closeText: { color: p.infoText, fontWeight: '600', fontSize: 15 },
    });
