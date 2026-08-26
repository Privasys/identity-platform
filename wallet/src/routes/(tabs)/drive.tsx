// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Drive tab — browse the caller's confidential personal drive.
 *
 * Gated behind Settings → driveEnabled. The enclave resolves like the
 * identity verifier (store resolve API with hardcoded build fallback,
 * attestation-pinned either way); on mount the tab ensures the drive
 * session (connect + setupPersonalDrive over RA-TLS) and browses the
 * folder tree. The bell opens the share-requests screen, where raw
 * subs are decorated from the wallet's attribute referential.
 */

import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
    ActivityIndicator,
    Alert,
    Pressable,
    RefreshControl,
    ScrollView,
    StyleSheet,
    View as RNView,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { AttestationView } from '@/components/AttestationView';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { diffTrustedAttestation, type AttestationDiff } from '@/services/attestation-diff';
import { attestDrive, ensureDrive, type DriveAttestation, type DriveNode } from '@/services/drive';
import { useDriveNotificationsStore } from '@/stores/drive-notifications';
import { useTrustedAppsStore } from '@/stores/trusted-apps';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';

/**
 * File size for a list row.
 *
 * The UNIT is translated (some languages abbreviate bytes differently) but the
 * NUMBER is not localised: these are small, and thousands separators here
 * would only invite the grouping-inside-a-technical-value mistake that the
 * measurement rows must never make.
 */
function formatSize(bytes: number, t: TFunction): string {
    if (!bytes) return '';
    if (bytes < 1024) return t('drive.sizeBytes', { value: bytes });
    if (bytes < 1024 * 1024) return t('drive.sizeKb', { value: (bytes / 1024).toFixed(0) });
    return t('drive.sizeMb', { value: (bytes / (1024 * 1024)).toFixed(1) });
}

interface Crumb {
    id: string;
    name: string;
}

export default function DriveScreen() {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const [nodes, setNodes] = useState<DriveNode[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [path, setPath] = useState<Crumb[]>([]);
    const pendingCount = useDriveNotificationsStore(
        (s) => s.requests.filter((r) => !r.decision).length
    );

    // Approval gate (mirrors the ID-check verifier): the user approves the Drive
    // enclave on first connect and re-approves if its attestation changes.
    //   preparing → attest + trusted-app check
    //   approve   → show AttestationView (new enclave, or a changed one)
    //   ready     → approved (or already trusted + unchanged) → browse
    //   blocked   → attestation failed, or the user declined
    type Phase = 'preparing' | 'approve' | 'ready' | 'blocked';
    const [phase, setPhase] = useState<Phase>('preparing');
    const [att, setAtt] = useState<DriveAttestation | null>(null);
    const [attError, setAttError] = useState<string | null>(null);
    const [isChanged, setIsChanged] = useState(false);
    const [diff, setDiff] = useState<AttestationDiff | null>(null);
    const [challengeInFlight, setChallengeInFlight] = useState(false);
    const { getApp, isAttestationMatch, addOrUpdate: addTrustedApp } = useTrustedAppsStore();

    const folder = path.length > 0 ? path[path.length - 1] : null;

    /** Record the approved Drive enclave so we don't re-prompt until it changes. */
    const rememberDrive = useCallback(
        (a: DriveAttestation) => {
            addTrustedApp({
                rpId: a.origin,
                origin: a.origin,
                appName: a.displayName,
                mrenclave: a.attestation.mrenclave,
                mrtd: a.attestation.mrtd,
                rtmr1: a.attestation.rtmr1,
                rtmr2: a.attestation.rtmr2,
                codeHash: a.attestation.workload_code_hash,
                configRoot: a.attestation.workload_config_merkle_root,
                teeType: a.attestation.tee_type ?? 'tdx',
                lastVerified: Math.floor(Date.now() / 1000),
                credentialId: ''
            });
        },
        [addTrustedApp]
    );

    /** Attest the Drive enclave and decide whether the user must approve it. */
    const prepare = useCallback(async () => {
        setPhase('preparing');
        setAttError(null);
        try {
            const a = await attestDrive();
            const measurements = {
                mrenclave: a.attestation.mrenclave,
                mrtd: a.attestation.mrtd,
                rtmr1: a.attestation.rtmr1,
                rtmr2: a.attestation.rtmr2,
                codeHash: a.attestation.workload_code_hash,
                configRoot: a.attestation.workload_config_merkle_root
            };
            const trusted = getApp(a.origin);
            if (trusted && isAttestationMatch(a.origin, measurements)) {
                // Already approved on this device and unchanged: refresh + go.
                rememberDrive(a);
                setPhase('ready');
            } else {
                setIsChanged(!!trusted);
                setDiff(trusted ? diffTrustedAttestation(trusted, a.attestation) : null);
                setAtt(a);
                setPhase('approve');
            }
        } catch (e) {
            setAttError(e instanceof Error ? e.message : t('drive.verifyFailed'));
            setPhase('blocked');
        }
    }, [getApp, isAttestationMatch, rememberDrive]);

    const handleApproveDrive = useCallback(() => {
        if (!att) return;
        rememberDrive(att);
        setAtt(null);
        setPhase('ready');
    }, [att, rememberDrive]);

    const handleRejectDrive = useCallback(() => {
        setAtt(null);
        setAttError(t('drive.declined'));
        setPhase('blocked');
    }, []);

    /** "Challenge this enclave": re-attest in challenge mode with a fresh nonce. */
    const handleChallengeDrive = useCallback(async () => {
        setChallengeInFlight(true);
        try {
            setAtt(await attestDrive('challenge'));
        } catch (e) {
            Alert.alert(
                t('drive.challengeFailedTitle'),
                e instanceof Error ? e.message : t('drive.challengeFailedBody')
            );
        } finally {
            setChallengeInFlight(false);
        }
    }, []);

    const load = useCallback(async (target: Crumb | null, asRefresh = false) => {
        if (asRefresh) setRefreshing(true);
        else setLoading(true);
        setError(null);
        try {
            const s = await ensureDrive();
            if (!s) {
                setError(t('drive.notAvailable'));
                setNodes(null);
                return;
            }
            setNodes(
                target
                    ? await s.drive.listFolder(s.tenant.id, target.id)
                    : await s.drive.listRoot(s.tenant.id)
            );
        } catch (e) {
            setError(e instanceof Error ? e.message : t('drive.openFailed'));
            setNodes(null);
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    }, []);

    // Run the approval gate once on mount.
    useEffect(() => {
        void prepare();
        // Hydrate the notifications store so the bell badge is live.
        void useDriveNotificationsStore.getState().hydrate();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // Browse only after the enclave is approved (or already trusted).
    useEffect(() => {
        if (phase !== 'ready') return;
        void load(folder);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [phase, folder?.id]);

    const openFolder = (n: DriveNode) => {
        setPath((cur) => [...cur, { id: n.id, name: n.name }]);
    };
    const goBack = () => {
        setPath((cur) => cur.slice(0, -1));
    };

    // Approval / re-approval screen for the Drive enclave (full-screen, same
    // shared view as sign-in and ID check).
    if (phase === 'approve' && att) {
        return (
            <AttestationView
                attestation={att.attestation}
                rpId={att.origin}
                displayName={att.displayName}
                isChanged={isChanged}
                diff={diff}
                verificationLevel="fresh-as-verified"
                verification={{ status: 'verified', mode: att.mode, challenged: att.challenged }}
                onApprove={handleApproveDrive}
                onReject={handleRejectDrive}
                onChallenge={handleChallengeDrive}
                challengeInFlight={challengeInFlight}
            />
        );
    }

    return (
        <RNView style={styles.screen}>
            <RNView style={[styles.header, { paddingTop: insets.top + 16 }]}>
                <RNView style={styles.headerRow}>
                    <RNView style={styles.headerText}>
                        <Text style={styles.headerTitle}>{t('tabs.drive')}</Text>
                        <Text style={styles.headerSubtitle}>{t('drive.subtitle')}</Text>
                    </RNView>
                    <Pressable
                        style={styles.bell}
                        onPress={() => router.push('/drive-requests')}
                        accessibilityLabel={t('drive.shareRequests')}
                    >
                        <Ionicons name="notifications-outline" size={22} color="#FFFFFF" />
                        {pendingCount > 0 && (
                            <RNView style={styles.badge}>
                                <Text style={styles.badgeText}>
                                    {pendingCount > 9 ? '9+' : String(pendingCount)}
                                </Text>
                            </RNView>
                        )}
                    </Pressable>
                </RNView>
            </RNView>

            {path.length > 0 && (
                <RNView style={styles.crumbBar}>
                    <Pressable style={styles.crumbBack} onPress={goBack}>
                        <Ionicons name="chevron-back" size={18} color={p.blue} />
                        <Text style={styles.crumbBackText}>
                            {path.length > 1 ? path[path.length - 2].name : t('tabs.drive')}
                        </Text>
                    </Pressable>
                    <Text style={styles.crumbHere} numberOfLines={1}>
                        {folder?.name}
                    </Text>
                </RNView>
            )}

            <RNView style={styles.content}>
                {phase === 'preparing' || (phase === 'ready' && loading) ? (
                    <ActivityIndicator style={styles.spinner} size="large" color={p.blue} />
                ) : phase === 'blocked' ? (
                    <RNView style={styles.emptyState}>
                        <Ionicons name="lock-closed-outline" size={44} color={p.textMuted} />
                        <Text style={styles.emptyText}>{attError ?? t('drive.couldNotVerify')}</Text>
                        <Pressable style={styles.retry} onPress={() => void prepare()}>
                            <Text style={styles.retryText}>{t('common.retry')}</Text>
                        </Pressable>
                    </RNView>
                ) : error ? (
                    <RNView style={styles.emptyState}>
                        <Ionicons name="cloud-offline-outline" size={44} color={p.textMuted} />
                        <Text style={styles.emptyText}>{error}</Text>
                        <Pressable style={styles.retry} onPress={() => void load(folder)}>
                            <Text style={styles.retryText}>{t('common.retry')}</Text>
                        </Pressable>
                    </RNView>
                ) : nodes && nodes.length === 0 ? (
                    <RNView style={styles.emptyState}>
                        <Ionicons name="folder-open-outline" size={44} color={p.textMuted} />
                        <Text style={styles.emptyText}>
                            {folder ? t('drive.folderEmpty') : t('drive.driveEmpty')}
                        </Text>
                    </RNView>
                ) : (
                    <ScrollView
                        contentContainerStyle={[styles.list, { paddingBottom: insets.bottom + 32 }]}
                        showsVerticalScrollIndicator={false}
                        refreshControl={
                            <RefreshControl
                                refreshing={refreshing}
                                onRefresh={() => void load(folder, true)}
                            />
                        }
                    >
                        {(nodes ?? []).map((n) => (
                            <Pressable
                                key={n.id}
                                style={styles.card}
                                disabled={n.kind !== 'folder'}
                                onPress={() => openFolder(n)}
                            >
                                <RNView
                                    style={[
                                        styles.icon,
                                        { backgroundColor: n.kind === 'folder' ? p.blue : '#8B5CF6' }
                                    ]}
                                >
                                    <Ionicons
                                        name={n.kind === 'folder' ? 'folder' : 'document'}
                                        size={18}
                                        color="#FFFFFF"
                                    />
                                </RNView>
                                <RNView style={styles.info}>
                                    <Text style={styles.name} numberOfLines={1}>
                                        {n.name}
                                    </Text>
                                    <Text style={styles.meta}>
                                        {n.kind === 'folder'
                                            ? t('drive.folder')
                                            : formatSize(n.size_bytes, t) || t('drive.file')}
                                    </Text>
                                </RNView>
                                {n.kind === 'folder' && (
                                    <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                                )}
                            </Pressable>
                        ))}
                    </ScrollView>
                )}
            </RNView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    header: {
        backgroundColor: p.green,
        paddingHorizontal: 24,
        paddingBottom: 32,
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28
    },
    headerRow: { flexDirection: 'row', alignItems: 'flex-start' },
    headerText: { flex: 1 },
    headerTitle: { fontSize: 28, fontWeight: '700', color: '#FFFFFF', letterSpacing: -0.5, marginBottom: 4 },
    headerSubtitle: { fontSize: 15, color: 'rgba(255,255,255,0.8)' },
    bell: {
        width: 40,
        height: 40,
        borderRadius: 20,
        backgroundColor: 'rgba(255,255,255,0.15)',
        alignItems: 'center',
        justifyContent: 'center'
    },
    badge: {
        position: 'absolute',
        top: -2,
        right: -2,
        minWidth: 18,
        height: 18,
        borderRadius: 9,
        backgroundColor: '#DC2626',
        alignItems: 'center',
        justifyContent: 'center',
        paddingHorizontal: 4
    },
    badgeText: { fontSize: 10, fontWeight: '700', color: '#FFFFFF' },
    crumbBar: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingHorizontal: 16,
        paddingVertical: 10,
        gap: 10
    },
    crumbBack: { flexDirection: 'row', alignItems: 'center', gap: 2 },
    crumbBackText: { fontSize: 14, fontWeight: '600', color: p.blue },
    crumbHere: { flex: 1, fontSize: 14, color: p.textSecondary, textAlign: 'right' },
    content: { flex: 1 },
    spinner: { marginTop: 60 },
    list: { padding: 20, paddingTop: 16, paddingBottom: 96 },
    emptyState: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 40, gap: 12 },
    emptyText: { fontSize: 15, textAlign: 'center', color: p.textSecondary, lineHeight: 22 },
    retry: {
        marginTop: 8,
        backgroundColor: p.blue,
        borderRadius: 12,
        paddingHorizontal: 20,
        paddingVertical: 10
    },
    retryText: { color: '#FFFFFF', fontSize: 15, fontWeight: '600' },
    card: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: p.card,
        borderRadius: 16,
        padding: 16,
        marginBottom: 10,
        shadowColor: '#0F172A',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.06,
        shadowRadius: 8,
        elevation: 2
    },
    icon: {
        width: 40,
        height: 40,
        borderRadius: 12,
        alignItems: 'center',
        justifyContent: 'center',
        marginRight: 14
    },
    info: { flex: 1 },
    name: { fontSize: 16, fontWeight: '600', color: p.textPrimary },
    meta: { fontSize: 12, color: p.textSecondary, marginTop: 2 }
});
