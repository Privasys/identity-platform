// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Drive: the holder's storage, opened from Profile. Two sections, My files
 * and Shared with me, read through the wallet's storage service
 * (services/drive-files); a file opens in the wallet's own viewer
 * (routes/drive-file).
 *
 * The Drive enclave is approved on first connect and re-approved if its
 * attestation changes, as for the identity verifier. A Drive link (an access
 * request approved, `/#shared/<tenant>/<node>`) arrives as `tenant` and
 * `node`, and is followed only when it came from the Drive this screen just
 * attested (`from` is the app id the platform named for the push).
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
import { useTranslation } from 'react-i18next';

import { AttestationView } from '@/components/AttestationView';
import { useHeaderTint, usePane } from '@/components/pane';
import { SubPageHeader } from '@/components/SubPageHeader';
import { PaneProvider } from '@/components/PaneProvider';
import { ChooseItem, emptyListWidth, LIST_WIDTH, SHEET_WIDTH } from '@/components/WideFrame';
import { DriveFileView, type DriveFileParams } from '@/routes/drive-file';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { diffTrustedAttestation, type AttestationDiff } from '@/services/attestation-diff';
import { attestDrive, type DriveAttestation } from '@/services/drive';
import {
    clearViewerCopies,
    DRIVE_ID,
    fileKind,
    formatSize,
    listFolder,
    listSharedWithMe,
    myTenant,
    type SharedItem,
    type StoredItem,
} from '@/services/drive-files';
import { useDriveNotificationsStore } from '@/stores/drive-notifications';
import { useTrustedAppsStore } from '@/stores/trusted-apps';
import { waitsForOperator } from '@/services/drive-key-approval';

type Section = 'mine' | 'shared';

/** The icon and colour of a row: folders, then each kind the viewer knows. */
function itemLook(it: StoredItem): { icon: React.ComponentProps<typeof Ionicons>['name']; colour: string } {
    if (it.kind === 'folder') return { icon: 'folder', colour: '#00BCF2' };
    switch (fileKind(it)) {
        case 'pdf':
            return { icon: 'document-text', colour: '#E5484D' };
        case 'image':
            return { icon: 'image', colour: '#12A594' };
        case 'markdown':
        case 'text':
            return { icon: 'reader', colour: '#8B5CF6' };
        default:
            return { icon: 'document', colour: '#64748B' };
    }
}

interface Crumb {
    tenantId: string;
    id: string;
    name: string;
}

function sameApp(a?: string, b?: string): boolean {
    const n = (s?: string) => (s ?? '').toLowerCase().replace(/-/g, '');
    return !!n(a) && n(a) === n(b);
}

export default function DriveScreen() {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const params = useLocalSearchParams<{ tenant?: string; node?: string; from?: string; section?: string }>();
    const [section, setSection] = useState<Section>(params.section === 'shared' || params.node ? 'shared' : 'mine');
    const [items, setItems] = useState<StoredItem[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [path, setPath] = useState<Crumb[]>([]);
    const [highlight, setHighlight] = useState<string | null>(null);
    const followed = useRef(false);
    // On a wide enough window the open file is drawn beside the list.
    const pane = usePane();
    const twoPane = !!pane?.twoPane && pane.kind === 'list';
    const tint = useHeaderTint();
    const [open, setOpen] = useState<(DriveFileParams & { id: string }) | null>(null);
    const pendingCount = useDriveNotificationsStore((s) => s.requests.filter((r) => !r.decision).length);

    // Approval gate: approve the Drive enclave on first connect, again if its
    // attestation changes.
    type Phase = 'preparing' | 'approve' | 'ready' | 'blocked';
    const [phase, setPhase] = useState<Phase>('preparing');
    const [att, setAtt] = useState<DriveAttestation | null>(null);
    const [driveAppId, setDriveAppId] = useState<string | null>(null);
    const [attError, setAttError] = useState<string | null>(null);
    const [isChanged, setIsChanged] = useState(false);
    const [diff, setDiff] = useState<AttestationDiff | null>(null);
    const [challengeInFlight, setChallengeInFlight] = useState(false);
    const { getApp, isAttestationMatch, addOrUpdate: addTrustedApp } = useTrustedAppsStore();

    const folder = path.length > 0 ? path[path.length - 1] : null;

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
                credentialId: '',
            });
        },
        [addTrustedApp],
    );

    const prepare = useCallback(async () => {
        setPhase('preparing');
        setAttError(null);
        try {
            const a = await attestDrive();
            setDriveAppId(a.appId);
            const measurements = {
                mrenclave: a.attestation.mrenclave,
                mrtd: a.attestation.mrtd,
                rtmr1: a.attestation.rtmr1,
                rtmr2: a.attestation.rtmr2,
                codeHash: a.attestation.workload_code_hash,
                configRoot: a.attestation.workload_config_merkle_root,
            };
            const trusted = getApp(a.origin);
            if (trusted && isAttestationMatch(a.origin, measurements)) {
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
    }, [getApp, isAttestationMatch, rememberDrive, t]);

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
    }, [t]);

    const handleChallengeDrive = useCallback(async () => {
        setChallengeInFlight(true);
        try {
            setAtt(await attestDrive('challenge'));
        } catch (e) {
            Alert.alert(t('drive.challengeFailedTitle'), e instanceof Error ? e.message : t('drive.challengeFailedBody'));
        } finally {
            setChallengeInFlight(false);
        }
    }, [t]);

    const load = useCallback(
        async (sec: Section, at: Crumb | null, asRefresh = false): Promise<StoredItem[] | null> => {
            if (asRefresh) setRefreshing(true);
            else setLoading(true);
            setError(null);
            try {
                const list = at
                    ? await listFolder(at.tenantId, at.id)
                    : sec === 'shared'
                      ? await listSharedWithMe()
                      : await listFolder(await myTenant());
                setItems(list);
                return list;
            } catch (e) {
                setError(
                    e instanceof Error
                        ? waitsForOperator(e.message)
                            ? t('drive.keyWaitsForOperator')
                            : e.message
                        : t('drive.openFailed'),
                );
                setItems(null);
                return null;
            } finally {
                setLoading(false);
                setRefreshing(false);
            }
        },
        [t],
    );

    const openItem = useCallback(
        (it: StoredItem) => {
            if (it.kind === 'folder') {
                setPath((cur) => [...cur, { tenantId: it.tenantId, id: it.id, name: it.name }]);
                return;
            }
            const file = { tenant: it.tenantId, id: it.id, name: it.name, mime: it.mime ?? '', size: String(it.sizeBytes) };
            if (twoPane) setOpen(file);
            else router.push({ pathname: '/drive-file', params: file });
        },
        [router, twoPane],
    );

    useEffect(() => {
        void prepare();
        void useDriveNotificationsStore.getState().hydrate();
        // Copies left by a viewer that never closed cleanly.
        clearViewerCopies();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // Browse once approved. The first load in Shared with me also follows a
    // Drive link, when it came from this Drive.
    useEffect(() => {
        if (phase !== 'ready') return;
        void (async () => {
            const list = await load(section, folder);
            if (followed.current || !list || folder || section !== 'shared') return;
            const { tenant, node, from } = params;
            if (!tenant || !node || !DRIVE_ID.test(tenant) || !DRIVE_ID.test(node)) return;
            followed.current = true;
            if (from && !sameApp(from, driveAppId ?? undefined)) return;
            const hit = (list as SharedItem[]).find((s) => s.tenantId === tenant && s.id === node);
            if (!hit) {
                Alert.alert(t('drive.notFound'));
                return;
            }
            setHighlight(hit.id);
            openItem(hit);
        })();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [phase, section, folder?.id]);

    const switchTo = (sec: Section) => {
        if (sec === section) return;
        setPath([]);
        setItems(null);
        setSection(sec);
    };

    if (phase === 'approve' && att) {
        // A request to answer: a task's width, as the sign-in sheet has.
        return (
            <RNView style={pane ? styles.taskWrap : styles.screen}>
                <RNView style={pane ? [styles.task, { width: Math.min(SHEET_WIDTH, pane.width - 48) }] : styles.screen}>
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
                </RNView>
            </RNView>
        );
    }

    const rootName = section === 'shared' ? t('drive.shared') : t('drive.mine');

    const list = (
        <RNView
            style={[
                styles.screen,
                twoPane && styles.listPane,
                twoPane && { width: open ? LIST_PANE_WIDTH : emptyListWidth(pane?.width ?? 0) },
            ]}
        >
            <SubPageHeader
                title={t('tabs.drive')}
                right={
                    <Pressable
                        style={styles.bell}
                        onPress={() => router.push('/drive-requests')}
                        accessibilityLabel={t('drive.shareRequests')}
                    >
                        <Ionicons name="notifications-outline" size={20} color={tint} />
                        {pendingCount > 0 && (
                            <RNView style={styles.badge}>
                                <Text style={styles.badgeText}>{pendingCount > 9 ? '9+' : String(pendingCount)}</Text>
                            </RNView>
                        )}
                    </Pressable>
                }
            />

            <RNView style={styles.segments} accessibilityRole="tablist">
                {(['mine', 'shared'] as Section[]).map((s) => (
                    <Pressable
                        key={s}
                        testID={`drive-section-${s}`}
                        style={[styles.segment, section === s && styles.segmentOn]}
                        onPress={() => switchTo(s)}
                        accessibilityRole="tab"
                        accessibilityState={{ selected: section === s }}
                    >
                        <Text style={[styles.segmentText, section === s && styles.segmentTextOn]}>
                            {s === 'shared' ? t('drive.shared') : t('drive.mine')}
                        </Text>
                    </Pressable>
                ))}
            </RNView>

            {path.length > 0 && (
                <RNView style={styles.crumbBar}>
                    <Pressable style={styles.crumbBack} onPress={() => setPath((cur) => cur.slice(0, -1))}>
                        <Ionicons name="chevron-back" size={18} color={p.blue} />
                        <Text style={styles.crumbBackText}>{path.length > 1 ? path[path.length - 2].name : rootName}</Text>
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
                        <Pressable style={styles.retry} onPress={() => void load(section, folder)}>
                            <Text style={styles.retryText}>{t('common.retry')}</Text>
                        </Pressable>
                    </RNView>
                ) : items && items.length === 0 ? (
                    <RNView style={styles.emptyState}>
                        <Ionicons
                            name={section === 'shared' && !folder ? 'people-outline' : 'folder-open-outline'}
                            size={44}
                            color={p.textMuted}
                        />
                        <Text style={styles.emptyText}>
                            {folder ? t('drive.folderEmpty') : section === 'shared' ? t('drive.sharedEmpty') : t('drive.driveEmpty')}
                        </Text>
                    </RNView>
                ) : (
                    <ScrollView
                        contentContainerStyle={[styles.list, { paddingBottom: insets.bottom + 32 }]}
                        showsVerticalScrollIndicator={false}
                        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={() => void load(section, folder, true)} />}
                    >
                        {(items ?? []).map((it) => {
                            const shared = section === 'shared' && !folder ? (it as SharedItem) : null;
                            const meta = [
                                it.kind === 'folder' ? t('drive.folder') : formatSize(it.sizeBytes, t) || t('drive.file'),
                                shared ? (shared.scope === 'write' ? t('drive.sharedCanEdit') : t('drive.sharedWithYou')) : '',
                            ]
                                .filter(Boolean)
                                .join(' · ');
                            return (
                                <Pressable
                                    key={`${it.tenantId}/${it.id}`}
                                    testID={`drive-item-${it.id}`}
                                    style={[styles.card, highlight === it.id && styles.cardHighlight]}
                                    onPress={() => openItem(it)}
                                    accessibilityRole="button"
                                    accessibilityLabel={it.name}
                                >
                                    <RNView style={[styles.icon, { backgroundColor: itemLook(it).colour }]}>
                                        <Ionicons name={itemLook(it).icon} size={18} color="#FFFFFF" />
                                    </RNView>
                                    <RNView style={styles.info}>
                                        <Text style={styles.name} numberOfLines={1}>
                                            {it.name}
                                        </Text>
                                        <Text style={styles.meta}>{meta}</Text>
                                    </RNView>
                                    <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                                </Pressable>
                            );
                        })}
                    </ScrollView>
                )}
            </RNView>
        </RNView>
    );
    if (!twoPane || !pane) return list;
    // Nothing open: the list is the wider column, and the second waits for a
    // file. A file opens beside a narrowed list; its close button widens it again.
    return (
        <RNView style={styles.split}>
            {list}
            {open ? (
                <RNView style={styles.detailPane}>
                    <PaneProvider kind="detail" width={pane.width - LIST_PANE_WIDTH} twoPane close={() => setOpen(null)}>
                        <DriveFileView key={`${open.tenant}/${open.id}`} params={open} />
                    </PaneProvider>
                </RNView>
            ) : (
                <ChooseItem />
            )}
        </RNView>
    );
}

/** The list's width when the open file is drawn beside it. */
const LIST_PANE_WIDTH = LIST_WIDTH;

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        screen: { flex: 1, backgroundColor: p.screenBg },
        split: { flex: 1, flexDirection: 'row', backgroundColor: p.screenBg },
        listPane: {
            flex: 0,
            borderRightWidth: StyleSheet.hairlineWidth,
            borderRightColor: p.border,
        },
        detailPane: { flex: 1, minWidth: 0 },
        taskWrap: { flex: 1, alignItems: 'center', backgroundColor: p.screenBg },
        task: { flex: 1 },
        bell: {
            width: 36,
            height: 36,
            borderRadius: 18,
            backgroundColor: 'rgba(255,255,255,0.2)',
            alignItems: 'center',
            justifyContent: 'center',
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
            paddingHorizontal: 4,
        },
        badgeText: { fontSize: 10, fontWeight: '700', color: '#FFFFFF' },
        segments: {
            flexDirection: 'row',
            marginHorizontal: 20,
            marginTop: 16,
            padding: 3,
            borderRadius: 12,
            backgroundColor: p.buttonNeutral,
        },
        segment: { flex: 1, paddingVertical: 8, borderRadius: 9, alignItems: 'center' },
        segmentOn: { backgroundColor: p.card },
        segmentText: { fontSize: 14, fontWeight: '600', color: p.textSecondary },
        segmentTextOn: { color: p.textPrimary },
        crumbBar: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 16, paddingTop: 10, gap: 10 },
        crumbBack: { flexDirection: 'row', alignItems: 'center', gap: 2 },
        crumbBackText: { fontSize: 14, fontWeight: '600', color: p.blue },
        crumbHere: { flex: 1, fontSize: 14, color: p.textSecondary, textAlign: 'right' },
        content: { flex: 1 },
        spinner: { marginTop: 60 },
        list: { padding: 20, paddingTop: 16, paddingBottom: 96 },
        emptyState: { flex: 1, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 40, gap: 12 },
        emptyText: { fontSize: 15, textAlign: 'center', color: p.textSecondary, lineHeight: 22 },
        retry: { marginTop: 8, backgroundColor: p.action, borderRadius: 12, paddingHorizontal: 20, paddingVertical: 10 },
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
            elevation: 2,
        },
        cardHighlight: { borderWidth: 1, borderColor: p.successBorder, backgroundColor: p.successBg, padding: 15 },
        icon: { width: 40, height: 40, borderRadius: 12, alignItems: 'center', justifyContent: 'center', marginRight: 14 },
        info: { flex: 1 },
        name: { fontSize: 16, fontWeight: '600', color: p.textPrimary },
        meta: { fontSize: 12, color: p.textSecondary, marginTop: 2 },
    });
