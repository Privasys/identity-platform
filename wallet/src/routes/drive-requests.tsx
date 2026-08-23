// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Drive share requests screen.
 *
 * Owner side: pending access requests on things the user shared via a
 * restricted link. The requester's presented attributes arrived in the
 * sealed push payload and live ONLY in the wallet's referential (the
 * drive stores subs, the wallet stores names) — this screen is where
 * the owner sees who is asking, and approves or denies with a
 * biometric gate. The decision itself runs over the attested RA-TLS
 * transport to the drive enclave.
 *
 * Requester side: updates on requests the user filed (approved or
 * denied) appear below the pending list.
 */

import { Ionicons } from '@expo/vector-icons';
import * as LocalAuthentication from 'expo-local-authentication';
import { useCallback, useEffect, useState } from 'react';
import {
    ActivityIndicator,
    Alert,
    Pressable,
    RefreshControl,
    ScrollView,
    StyleSheet,
    View as RNView,
} from 'react-native';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { decideShareRequest, listShareRequests } from '@/services/drive';
import {
    useDriveNotificationsStore,
    type ShareRequest,
} from '@/stores/drive-notifications';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';

/**
 * Human label for a canonical attribute key. Unknown keys fall back to the
 * key itself, title-cased, which is language-neutral and better than a
 * missing-translation marker for a value the drive chose.
 */
function attrLabel(key: string, t: TFunction): string {
    const keys: Record<string, string> = {
        name: 'driveRequests.attrName',
        email: 'driveRequests.attrEmail',
        organisation: 'driveRequests.attrOrganisation',
        organization: 'driveRequests.attrOrganisation',
        phone: 'driveRequests.attrPhone',
        country: 'driveRequests.attrCountry',
    };
    const k = keys[key];
    return k ? t(k) : key.charAt(0).toUpperCase() + key.slice(1);
}

function timeAgo(epochSeconds: number, t: TFunction): string {
    const s = Math.max(0, Math.floor(Date.now() / 1000) - epochSeconds);
    if (s < 60) return t('time.justNow');
    if (s < 3600) return t('time.minutesAgo', { count: Math.floor(s / 60) });
    if (s < 86400) return t('time.hoursAgo', { count: Math.floor(s / 3600) });
    return t('time.daysAgo', { count: Math.floor(s / 86400) });
}

export default function DriveRequestsScreen() {
    const { t } = useTranslation();
    const palette = usePalette();
    const styles = makeStyles(palette);
    const store = useDriveNotificationsStore();
    const [busy, setBusy] = useState<string | null>(null);
    const [refreshing, setRefreshing] = useState(false);
    const [syncNote, setSyncNote] = useState<string | null>(null);

    // The drive's own request list is the source of truth: pushes whose
    // sealed payload never arrived (older wallet, key registered after
    // send) still appear, and decisions made elsewhere reconcile in.
    const syncFromDrive = useCallback(async () => {
        try {
            const { tenantId, requests } = await listShareRequests();
            useDriveNotificationsStore.getState().syncServer(tenantId, requests);
            setSyncNote(null);
        } catch (e) {
            // Local pushes still render; say why the list may be stale.
            setSyncNote(e instanceof Error ? e.message : t('driveRequests.unreachable'));
        }
    }, []);

    useEffect(() => {
        void (async () => {
            await store.hydrate();
            await syncFromDrive();
        })();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    const onRefresh = useCallback(async () => {
        setRefreshing(true);
        await syncFromDrive();
        setRefreshing(false);
    }, [syncFromDrive]);

    const pending = store.pendingRequests();
    const handled = store.requests.filter((r) => r.decision);
    const decisions = [...store.decisions].sort((a, b) => b.receivedAt - a.receivedAt);

    const decide = useCallback(
        async (req: ShareRequest, decision: 'approve' | 'deny') => {
            const auth = await LocalAuthentication.authenticateAsync({
                promptMessage: decision === 'approve'
                    ? t('driveRequests.promptApprove', { item: req.nodeName })
                    : t('driveRequests.promptDeny', { item: req.nodeName }),
            });
            if (!auth.success) return;
            setBusy(req.requestId);
            try {
                await decideShareRequest(req.tenantId, req.requestId, decision);
                store.markDecided(req.requestId, decision === 'approve' ? 'approved' : 'denied');
            } catch (e) {
                Alert.alert(
                    t('driveRequests.decisionFailedTitle'),
                    e instanceof Error ? e.message : t('driveRequests.decisionFailedBody')
                );
            } finally {
                setBusy(null);
            }
        },
        [store]
    );

    return (
        <RNView style={styles.container}>
            <SubPageHeader title={t('driveRequests.title')} />
            <ScrollView
                contentContainerStyle={styles.scroll}
                refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => void onRefresh()} />}
            >
                {syncNote && (
                    <RNView style={styles.syncNote}>
                        <Ionicons name="cloud-offline-outline" size={16} color={palette.warnText} />
                        <Text style={styles.syncNoteText}>{t('driveRequests.syncNote')}</Text>
                    </RNView>
                )}
                <Text style={styles.sectionTitle}>{t('driveRequests.awaiting')}</Text>
                {pending.length === 0 && (
                    <RNView style={styles.emptyCard}>
                        <Ionicons name="checkmark-circle-outline" size={22} color={palette.textMuted} />
                        <Text style={styles.emptyText}>{t('driveRequests.noPending')}</Text>
                    </RNView>
                )}
                {pending.map((req) => {
                    const who = store.lookup(req.requesterSub);
                    const attrs = Object.entries(who?.attributes ?? {});
                    return (
                        <RNView key={req.requestId} style={styles.card}>
                            <RNView style={styles.cardHeader}>
                                <Ionicons name="document-lock-outline" size={20} color={palette.action} />
                                <Text style={styles.nodeName} numberOfLines={1}>
                                    {req.nodeName || t('driveRequests.sharedItem')}
                                </Text>
                                <Text style={styles.when}>{timeAgo(req.receivedAt, t)}</Text>
                            </RNView>
                            {attrs.length > 0 ? (
                                <RNView style={styles.attrs}>
                                    {attrs.map(([k, v]) => (
                                        <RNView key={k} style={styles.attrRow}>
                                            <Text style={styles.attrKey}>{attrLabel(k, t)}</Text>
                                            <Text style={styles.attrVal} numberOfLines={1}>
                                                {v}
                                            </Text>
                                        </RNView>
                                    ))}
                                </RNView>
                            ) : (
                                <Text style={styles.noAttrs}>
                                    {t('driveRequests.noAttributes', { requester: req.requesterSub.slice(0, 12) })}
                                </Text>
                            )}
                            <Text style={styles.scope}>
                                {t('driveRequests.requestedAccess', {
                                    scope: req.scope.join(', ') || t('driveRequests.scopeRead')
                                })}
                            </Text>
                            <RNView style={styles.actions}>
                                <Pressable
                                    style={[styles.btn, styles.btnDeny]}
                                    disabled={busy === req.requestId}
                                    onPress={() => void decide(req, 'deny')}
                                >
                                    <Text style={styles.btnDenyText}>{t('connect.deny')}</Text>
                                </Pressable>
                                <Pressable
                                    style={[styles.btn, styles.btnApprove]}
                                    disabled={busy === req.requestId}
                                    onPress={() => void decide(req, 'approve')}
                                >
                                    {busy === req.requestId ? (
                                        <ActivityIndicator color="#fff" size="small" />
                                    ) : (
                                        <Text style={styles.btnApproveText}>{t('attestation.approve')}</Text>
                                    )}
                                </Pressable>
                            </RNView>
                        </RNView>
                    );
                })}

                {decisions.length > 0 && (
                    <>
                        <Text style={styles.sectionTitle}>{t('driveRequests.yourRequests')}</Text>
                        {decisions.map((d) => (
                            <RNView key={`${d.requestId}-${d.status}`} style={styles.card}>
                                <RNView style={styles.cardHeader}>
                                    <Ionicons
                                        name={d.status === 'approved' ? 'lock-open-outline' : 'close-circle-outline'}
                                        size={20}
                                        color={d.status === 'approved' ? palette.successText : palette.dangerText}
                                    />
                                    <Text style={styles.nodeName} numberOfLines={1}>
                                        {d.nodeName || t('driveRequests.sharedItem')}
                                    </Text>
                                    <Text style={styles.when}>{timeAgo(d.receivedAt, t)}</Text>
                                </RNView>
                                <Text style={styles.decisionText}>
                                    {d.status === 'approved'
                                        ? t('driveRequests.yourRequestApproved')
                                        : t('driveRequests.yourRequestDenied')}
                                </Text>
                            </RNView>
                        ))}
                    </>
                )}

                {handled.length > 0 && (
                    <>
                        <Text style={styles.sectionTitle}>{t('driveRequests.handled')}</Text>
                        {handled
                            .slice()
                            .sort((a, b) => b.receivedAt - a.receivedAt)
                            .slice(0, 20)
                            .map((req) => {
                                const who = store.lookup(req.requesterSub);
                                const display =
                                    who?.attributes?.name ||
                                    who?.attributes?.email ||
                                    `${req.requesterSub.slice(0, 12)}…`;
                                return (
                                    <RNView key={req.requestId} style={styles.handledRow}>
                                        <Text style={styles.handledText} numberOfLines={1}>
                                            {display} · {req.nodeName}
                                        </Text>
                                        <Text
                                            style={[
                                                styles.handledBadge,
                                                req.decision === 'approved'
                                                    ? styles.badgeApproved
                                                    : styles.badgeDenied,
                                            ]}
                                        >
                                            {req.decision === 'approved'
                                                ? t('driveRequests.decisionApproved')
                                                : t('driveRequests.decisionDenied')}
                                        </Text>
                                    </RNView>
                                );
                            })}
                    </>
                )}
            </ScrollView>
        </RNView>
    );
}

function makeStyles(palette: Palette) {
    return StyleSheet.create({
        container: { flex: 1, backgroundColor: palette.screenBg },
        scroll: { padding: 16, paddingBottom: 40 },
        sectionTitle: {
            fontSize: 13,
            fontWeight: '600',
            color: palette.textMuted,
            textTransform: 'uppercase',
            letterSpacing: 0.5,
            marginTop: 18,
            marginBottom: 8,
        },
        emptyCard: {
            flexDirection: 'row',
            alignItems: 'center',
            gap: 8,
            backgroundColor: palette.card,
            borderRadius: 12,
            padding: 16,
        },
        syncNote: {
            flexDirection: 'row',
            alignItems: 'center',
            gap: 8,
            backgroundColor: palette.warnBg,
            borderColor: palette.warnBorder,
            borderWidth: 1,
            borderRadius: 10,
            padding: 10,
            marginTop: 12,
        },
        syncNoteText: { flex: 1, fontSize: 12, color: palette.warnText },
        emptyText: { color: palette.textMuted, fontSize: 14 },
        card: {
            backgroundColor: palette.card,
            borderRadius: 12,
            padding: 14,
            marginBottom: 10,
        },
        cardHeader: { flexDirection: 'row', alignItems: 'center', gap: 8 },
        nodeName: { flex: 1, fontSize: 15, fontWeight: '600' },
        when: { fontSize: 12, color: palette.textMuted },
        attrs: { marginTop: 10, gap: 4 },
        attrRow: { flexDirection: 'row', gap: 8 },
        attrKey: { width: 110, fontSize: 13, color: palette.textMuted },
        attrVal: { flex: 1, fontSize: 13, fontWeight: '500' },
        noAttrs: { marginTop: 10, fontSize: 13, color: palette.textMuted },
        scope: { marginTop: 8, fontSize: 12, color: palette.textMuted },
        actions: { flexDirection: 'row', gap: 10, marginTop: 12 },
        btn: {
            flex: 1,
            borderRadius: 10,
            paddingVertical: 10,
            alignItems: 'center',
            justifyContent: 'center',
        },
        btnApprove: { backgroundColor: palette.approve },
        btnApproveText: { color: '#fff', fontWeight: '600' },
        btnDeny: { backgroundColor: 'transparent', borderWidth: 1, borderColor: palette.border },
        btnDenyText: { color: palette.textPrimary, fontWeight: '600' },
        decisionText: { marginTop: 8, fontSize: 13, color: palette.textMuted },
        handledRow: {
            flexDirection: 'row',
            alignItems: 'center',
            justifyContent: 'space-between',
            paddingVertical: 8,
            gap: 10,
        },
        handledText: { flex: 1, fontSize: 13, color: palette.textMuted },
        handledBadge: {
            fontSize: 11,
            fontWeight: '600',
            paddingHorizontal: 8,
            paddingVertical: 2,
            borderRadius: 8,
            overflow: 'hidden',
        },
        badgeApproved: { backgroundColor: 'rgba(22,163,74,0.12)', color: '#16a34a' },
        badgeDenied: { backgroundColor: 'rgba(220,38,38,0.12)', color: '#dc2626' },
    });
}
