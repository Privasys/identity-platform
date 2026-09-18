// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Access: everything that can currently act on the holder, in one place.
 *
 * This tab replaced a list of sessions. A session list is something you
 * consult, not something you land on, and the answer the holder actually wants
 * when they open the wallet is "what can reach me, and how do I stop it".
 *
 * The order is deliberate. Anything needing a decision comes first. Then the
 * two kinds of standing access, because those are the ones a holder forgets
 * they granted, with connected accounts above their own data since a credential
 * handed to someone else is the one they can least afford to lose track of.
 * Sign-ins and history sit underneath, as references rather than controls.
 */

import { Ionicons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { sectionTitleStyle } from '@/components/section-title';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { rebuildFromGrantsIndex, syncGrantsIndex } from '@/services/grants-index';
import { useAuthStore } from '@/stores/auth';
import { useCapabilitiesStore } from '@/stores/capabilities';
import { useConsentStore } from '@/stores/consent';
import { useProfileStore } from '@/stores/profile';
import { useServiceSessionsStore } from '@/stores/service-sessions';
import { useSessionsStore } from '@/stores/sessions';
import { useTrustedAppsStore } from '@/stores/trusted-apps';
import { useVaultApprovalsStore } from '@/stores/vaultApprovals';
import { isLive, rowsInGroup, type AccessRow } from '@/utils/access-rows';
import { buildSessionRows, relativeWhen } from '@/utils/session-rows';

/** How many rows a section shows before it defers to its own screen. */
const PREVIEW = 3;

export default function AccessScreen() {
    const { apps } = useTrustedAppsStore();
    const traces = useServiceSessionsStore((s) => s.traces);
    const sessions = useSessionsStore((s) => s.sessions);
    const records = useCapabilitiesStore((s) => s.records);
    const hydrateCapabilities = useCapabilitiesStore((s) => s.hydrate);
    const credentials = useAuthStore((s) => s.credentials);
    const recoveryPhraseSaved = useAuthStore((s) => s.recoveryPhraseSaved);
    const consentRecordCount = useConsentStore((s) => s.records.length);
    const pendingApprovals = useVaultApprovalsStore((s) => s.pending);
    const refreshApprovals = useVaultApprovalsStore((s) => s.refresh);
    const hasProfile = useProfileStore((s) => !!s.profile);
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { t } = useTranslation();
    const [now, setNow] = useState(() => Date.now());

    useEffect(() => {
        // Local rows first, then any this phone is missing from the services
        // the grants index names (a recovered or a second phone), then make
        // sure the index reflects what this phone now holds. Once per launch,
        // off the render path, and silent: a service that cannot be reached
        // leaves the rows the phone already had.
        void hydrateCapabilities()
            .then(() => rebuildFromGrantsIndex())
            .then(() => syncGrantsIndex());
    }, [hydrateCapabilities]);

    // A minute is enough here. Nothing on this screen counts down; the tick
    // only moves "2 hours ago" along and retires an expired grant.
    useEffect(() => {
        const id = setInterval(() => setNow(Date.now()), 60_000);
        return () => clearInterval(id);
    }, []);

    // Keep the pending count live: approvals arrive by push and also expire on
    // their own, so neither event is something this screen would otherwise see.
    useEffect(() => {
        void refreshApprovals();
        const id = setInterval(() => void refreshApprovals(), 20_000);
        return () => clearInterval(id);
    }, [refreshApprovals]);

    const nowSeconds = Math.floor(now / 1000);
    const sessionRows = useMemo(
        () => buildSessionRows(traces, apps, sessions, now),
        [traces, apps, sessions, now],
    );
    const accounts = useMemo(() => rowsInGroup(records, 'account'), [records]);
    const data = useMemo(() => rowsInGroup(records, 'data'), [records]);

    const openGrant = (row: AccessRow) =>
        router.push({ pathname: '/access-grant', params: { key: row.key } });

    return (
        <RNView style={styles.screen}>
            <RNView style={[styles.header, { paddingTop: insets.top + 16 }]}>
                <Text style={styles.headerTitle}>{t('tabs.access')}</Text>
            </RNView>

            <ScrollView
                style={styles.body}
                contentContainerStyle={[styles.bodyContent, { paddingBottom: insets.bottom + 110 }]}
                showsVerticalScrollIndicator={false}
            >
                {/* Anything wanting a decision, before anything to browse. */}
                {hasProfile && !recoveryPhraseSaved && (
                    <Pressable
                        style={styles.banner}
                        onPress={() => router.push('/account-recovery')}
                        accessibilityLabel={t('home.savePhraseTitle')}
                    >
                        <RNView style={[styles.bannerIcon, { backgroundColor: '#FDE68A' }]}>
                            <Ionicons name="key-outline" size={18} color="#B45309" />
                        </RNView>
                        <RNView style={styles.bannerInfo}>
                            <Text style={styles.bannerTitle}>{t('home.savePhraseTitle')}</Text>
                            <Text style={styles.bannerMeta}>{t('home.savePhraseBody')}</Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                    </Pressable>
                )}

                {pendingApprovals.length > 0 && (
                    <Pressable
                        style={styles.banner}
                        onPress={() => router.push('/vault-approvals')}
                        accessibilityLabel={t('home.pendingVaultApprovals', {
                            count: pendingApprovals.length,
                        })}
                    >
                        <RNView style={styles.bannerIcon}>
                            <Ionicons name="key" size={18} color={p.infoText} />
                        </RNView>
                        <RNView style={styles.bannerInfo}>
                            <Text style={styles.bannerTitle}>
                                {t('home.pendingApprovals', { count: pendingApprovals.length })}
                            </Text>
                            <Text style={styles.bannerMeta}>{t('home.pendingApprovalsHint')}</Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color={p.infoText} />
                    </Pressable>
                )}

                {/* Connected accounts: a credential of the holder's, held by a
                    service, for an account somewhere we do not control. Only
                    when there is one: an empty section explaining a concept
                    the holder has not met is noise. */}
                {accounts.length > 0 && (
                    <Section
                        title={t('access.accountsTitle')}
                        hint={t('access.accountsHint')}
                        styles={styles}
                    >
                        <>
                            {accounts.slice(0, PREVIEW).map((row) => (
                                <GrantRow
                                    key={row.key}
                                    row={row}
                                    nowSeconds={nowSeconds}
                                    onPress={() => openGrant(row)}
                                    styles={styles}
                                    p={p}
                                    subtitle={row.record.resourceLabel}
                                />
                            ))}
                            {accounts.length > PREVIEW && (
                                <SeeAll
                                    label={t('access.seeAll')}
                                    onPress={() =>
                                        router.push({ pathname: '/access-list', params: { group: 'account' } })
                                    }
                                    styles={styles}
                                    p={p}
                                />
                            )}
                        </>
                    </Section>
                )}

                {/* Access to data we hold, where revoking is complete. Same
                    rule: shown once something has it. */}
                {data.length > 0 && (
                    <Section title={t('access.dataTitle')} hint={t('access.dataHint')} styles={styles}>
                        <>
                            {data.slice(0, PREVIEW).map((row) => (
                                <GrantRow
                                    key={row.key}
                                    row={row}
                                    nowSeconds={nowSeconds}
                                    onPress={() => openGrant(row)}
                                    styles={styles}
                                    p={p}
                                    subtitle={t('access.inService', {
                                        resource: row.record.resourceLabel,
                                        service: row.record.resourceAppName || t('capability.unnamedApp'),
                                    })}
                                />
                            ))}
                            {data.length > PREVIEW && (
                                <SeeAll
                                    label={t('access.seeAll')}
                                    onPress={() =>
                                        router.push({ pathname: '/access-list', params: { group: 'data' } })
                                    }
                                    styles={styles}
                                    p={p}
                                />
                            )}
                        </>
                    </Section>
                )}

                {/* Sessions: the three most recent, then the full list. This is
                    the fix for a box that grew to 33 rows and swallowed the
                    screen; nothing is hidden, it just is not all here. */}
                <Section
                    title={t('access.sessionsTitle')}
                    hint={t('access.sessionsHint')}
                    styles={styles}
                >
                    {sessionRows.length === 0 ? (
                        <Text style={styles.empty}>{t('home.noSessions')}</Text>
                    ) : (
                        <>
                            {sessionRows.slice(0, PREVIEW).map((row) => (
                                <Pressable
                                    key={row.key}
                                    style={styles.row}
                                    onPress={() =>
                                        router.push({
                                            pathname: '/service-detail',
                                            params: { serviceKey: row.key },
                                        })
                                    }
                                >
                                    <RNView style={styles.rowInfo}>
                                        <Text style={styles.rowTitle}>{row.name}</Text>
                                        <Text style={styles.rowMeta}>
                                            {relativeWhen(row.lastActiveMs, now, t)}
                                        </Text>
                                    </RNView>
                                    {row.session && <RNView style={styles.liveDot} />}
                                    <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                                </Pressable>
                            ))}
                            <SeeAll
                                label={t('access.seeAll')}
                                onPress={() => router.push('/sessions')}
                                styles={styles}
                                p={p}
                            />
                        </>
                    )}
                </Section>

                {/* References rather than controls. */}
                <Section title={t('access.recordTitle')} styles={styles}>
                    <Pressable style={styles.row} onPress={() => router.push('/credentials')}>
                        <RNView style={styles.rowInfo}>
                            <Text style={styles.rowTitle}>{t('access.credentials')}</Text>
                            <Text style={styles.rowMeta}>
                                {credentials.length > 0
                                    ? t('profile.registeredCredentialsCount', { count: credentials.length })
                                    : t('access.credentialsNone')}
                            </Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                    </Pressable>
                    <Pressable style={styles.row} onPress={() => router.push('/consent-history')}>
                        <RNView style={styles.rowInfo}>
                            <Text style={styles.rowTitle}>{t('access.sharingHistory')}</Text>
                            <Text style={styles.rowMeta}>
                                {consentRecordCount === 0
                                    ? t('profile.noSharingEvents')
                                    : t('profile.eventCount', { count: consentRecordCount })}
                            </Text>
                        </RNView>
                        <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
                    </Pressable>
                </Section>
            </ScrollView>

            {/* Scanning is how a service gets access, so it belongs here. */}
            <Pressable
                style={styles.scanFab}
                onPress={() => router.push('/scan')}
                accessibilityLabel={t('home.scanQrCode')}
            >
                <Ionicons name="qr-code-outline" size={26} color="#FFFFFF" />
            </Pressable>
        </RNView>
    );
}

function Section({
    title,
    hint,
    styles,
    children,
}: {
    title: string;
    hint?: string;
    styles: ReturnType<typeof makeStyles>;
    children: React.ReactNode;
}) {
    return (
        <RNView style={styles.section}>
            <Text style={styles.sectionTitle}>{title}</Text>
            {!!hint && <Text style={styles.sectionHint}>{hint}</Text>}
            <RNView style={styles.card}>{children}</RNView>
        </RNView>
    );
}

function SeeAll({
    label,
    onPress,
    styles,
    p,
}: {
    label: string;
    onPress: () => void;
    styles: ReturnType<typeof makeStyles>;
    p: Palette;
}) {
    return (
        <Pressable style={styles.seeAll} onPress={onPress}>
            <Text style={styles.seeAllText}>{label}</Text>
            <Ionicons name="chevron-forward" size={16} color={p.blue} />
        </Pressable>
    );
}

function GrantRow({
    row,
    subtitle,
    nowSeconds,
    onPress,
    styles,
    p,
}: {
    row: AccessRow;
    subtitle: string;
    nowSeconds: number;
    onPress: () => void;
    styles: ReturnType<typeof makeStyles>;
    p: Palette;
}) {
    const { t } = useTranslation();
    const live = isLive(row.record, nowSeconds);
    return (
        <Pressable style={styles.row} onPress={onPress}>
            <RNView style={styles.rowInfo}>
                <Text style={[styles.rowTitle, !live && styles.rowEnded]}>
                    {row.record.appName || t('capability.unnamedApp')}
                </Text>
                <Text style={styles.rowMeta}>{subtitle}</Text>
                {!live && (
                    <Text style={styles.rowEndedNote}>
                        {row.record.revokedAt ? t('access.stateRevoked') : t('access.stateEnded')}
                    </Text>
                )}
            </RNView>
            <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
        </Pressable>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    header: {
        backgroundColor: p.green,
        paddingHorizontal: 24,
        paddingBottom: 24,
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28,
    },
    // The same header as Profile and Settings: the tab's name, nothing else.
    headerTitle: {
        fontSize: 28,
        fontWeight: '700',
        color: '#FFFFFF',
        letterSpacing: -0.5,
    },
    body: { flex: 1 },
    bodyContent: { paddingHorizontal: 20, paddingTop: 16 },
    banner: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12,
        marginBottom: 16,
        backgroundColor: 'rgba(52, 232, 158, 0.12)',
        borderRadius: 14,
        paddingHorizontal: 14,
        paddingVertical: 14,
    },
    bannerIcon: {
        width: 36,
        height: 36,
        borderRadius: 18,
        backgroundColor: 'rgba(52, 232, 158, 0.22)',
        alignItems: 'center',
        justifyContent: 'center',
    },
    bannerInfo: { flex: 1 },
    bannerTitle: { fontSize: 15, fontWeight: '700', color: p.textPrimary },
    bannerMeta: { fontSize: 12, color: p.infoText, marginTop: 2 },
    section: { marginBottom: 20 },
    sectionTitle: { ...sectionTitleStyle(p), marginBottom: 4 },
    sectionHint: { fontSize: 13, color: p.textMuted, lineHeight: 18, marginBottom: 10 },
    card: { backgroundColor: p.card, borderRadius: 14, overflow: 'hidden' },
    row: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        paddingHorizontal: 16,
        paddingVertical: 14,
        borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: p.border,
    },
    rowInfo: { flex: 1, gap: 2 },
    rowTitle: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
    rowEnded: { color: p.textMuted },
    rowEndedNote: { fontSize: 12, color: p.textMuted },
    rowMeta: { fontSize: 13, color: p.textSecondary },
    liveDot: { width: 8, height: 8, borderRadius: 4, backgroundColor: p.green },
    empty: { fontSize: 13, color: p.textMuted, paddingHorizontal: 16, paddingVertical: 16 },
    seeAll: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 4,
        paddingVertical: 13,
    },
    seeAllText: { fontSize: 14, fontWeight: '600', color: p.blue },
    scanFab: {
        position: 'absolute',
        right: 24,
        bottom: 24,
        width: 60,
        height: 60,
        borderRadius: 30,
        backgroundColor: p.blue,
        alignItems: 'center',
        justifyContent: 'center',
        shadowColor: p.blue,
        shadowOffset: { width: 0, height: 6 },
        shadowOpacity: 0.4,
        shadowRadius: 12,
        elevation: 8,
    },
});
