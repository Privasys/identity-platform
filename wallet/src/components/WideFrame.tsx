// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The wallet on a wide window: tablets, and unfolded phones (iPhone Duo,
 * Android foldables). From WIDE_MIN_WIDTH a sidebar takes the tab bar's place
 * and the green header band goes. From TWO_PANE_MIN_WIDTH each section is two
 * columns: its own screen (Profile, Access, Settings, Drive) in the first,
 * and what it opens in the second. With nothing open the first column is the
 * wider one and the second waits for an item; when one opens, the first
 * narrows and the item has the room. A long screen scrolls in its column; it
 * never spills into the second. Tasks, which ask one thing at a time, are a
 * centred sheet.
 *
 * The root stack wraps every screen in this frame (its screenLayout), so the
 * routes stay as they are: a list item still pushes its route, and the frame
 * draws that route beside the list it came from. Below WIDE_MIN_WIDTH the
 * frame draws nothing of its own.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { usePathname, useRouter } from 'expo-router';
import { useMemo, useRef, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Image, Pressable, StyleSheet, useWindowDimensions, View } from 'react-native';
import { SafeAreaInsetsContext, useSafeAreaInsets } from 'react-native-safe-area-context';

import { PaneProvider } from '@/components/PaneProvider';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { columnGutter, READABLE_WIDTH, TWO_PANE_MIN_WIDTH, useWideLayout } from '@/hooks/useLargeScreen';
import ProfileScreen from '@/routes/(tabs)/index';
import AccessScreen from '@/routes/(tabs)/access';
import SettingsScreen from '@/routes/(tabs)/settings';
import { useAppMessagesStore } from '@/stores/app-messages';
import { useCapabilityAsksStore } from '@/stores/capability-asks';
import { useDriveNotificationsStore } from '@/stores/drive-notifications';
import { useGuardianRequestsStore, waitingCount } from '@/stores/guardian-requests';
import { primaryEmail, profileDisplayName } from '@/services/attributes';
import { useProfileStore } from '@/stores/profile';
import { useVaultApprovalsStore } from '@/stores/vaultApprovals';

type Section = 'profile' | 'drive' | 'access' | 'settings';

/** Routes that are a task: drawn as a centred sheet over the screen. */
export const TASK_ROUTES = new Set([
    'connect',
    'approval',
    'app-form',
    'capability-request',
    'access-grant',
    'vault-approvals',
    'app-lock',
    'kyc-capture',
    'verify-email',
    'account-recovery',
    'recover-account',
    'secure-wallet',
    'scan',
    'scp',
    'device-add',
    'device-send',
    'account/delete/confirm',
]);

/** The section each route belongs to, for the sidebar and the list beside it. */
const SECTION_OF: Record<string, Section> = {
    'access-app': 'access',
    'access-list': 'access',
    'access-provider': 'access',
    sessions: 'access',
    'service-detail': 'access',
    'consent-history': 'access',
    credentials: 'access',
    'drive-requests': 'drive',
    'drive-file': 'drive',
    identities: 'profile',
    'personal-data': 'profile',
    // Pages to browse, not one-off tasks: beside Profile, as its other rows.
    import: 'profile',
    export: 'profile',
    drive: 'drive',
    devices: 'settings',
    'how-it-works': 'settings',
    logs: 'settings',
    language: 'settings',
};

const SIDEBAR_WIDTH = 260;
const SIDEBAR_WIDTH_NARROW = 220;
/** The first column with an item open beside it. */
export const LIST_WIDTH = 400;
/** A task's width: the sheet, or a request answered inside a section. */
export const SHEET_WIDTH = 600;
const SHEET_MAX_HEIGHT = 820;

const NO_INSETS = { top: 0, bottom: 0, left: 0, right: 0 };

/** The first column with an item of Profile, Access or Settings open beside
 *  it: half the room, never narrower than a list needs. */
function openListWidth(rest: number): number {
    return Math.max(LIST_WIDTH, Math.min(Math.floor(rest / 2), emptyListWidth(rest)));
}

/** The first column with nothing open beside it: the wider one, up to a
 *  readable width, and never so wide the second column has no room. */
export function emptyListWidth(rest: number): number {
    return Math.max(LIST_WIDTH, Math.min(READABLE_WIDTH, Math.floor(rest * 0.55), rest - 360));
}

/** Whether the window shows the sidebar: wide, and the wallet set up (before
 *  that, onboarding keeps the centred column of a large screen). */
export function useSidebarLayout(): boolean {
    const wide = useWideLayout();
    const hasProfile = useProfileStore((s) => s.profile != null);
    return wide && hasProfile;
}

/** Everything waiting on a decision: the Access badge, on the tab bar and here. */
export function useWaitingCount(): number {
    const pending = useVaultApprovalsStore((s) => s.pending.length + s.batchIds.length);
    const asks = useCapabilityAsksStore((s) => s.asks.length);
    const guardian = useGuardianRequestsStore(waitingCount);
    const messages = useAppMessagesStore((s) => s.messages.length);
    return pending + asks + guardian + messages;
}

function tabSection(pathname: string): Section {
    if (pathname.startsWith('/access')) return 'access';
    if (pathname.startsWith('/settings')) return 'settings';
    return 'profile';
}

export function WideFrame({ routeName, children }: { routeName: string; children: ReactNode }) {
    const live = useSidebarLayout();
    // A task keeps the layout it opened with until it is left. Adding this
    // device gives the wallet its profile mid-task; redrawing the task in the
    // sidebar layout then would mount it afresh, and start it over.
    const opened = useRef<boolean | null>(null);
    if (opened.current === null) opened.current = live;
    const sidebar = TASK_ROUTES.has(routeName) ? opened.current : live;
    const pathname = usePathname();
    const { width } = useWindowDimensions();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const router = useRouter();

    // The phone layout, and the wallet before it has a profile (onboarding
    // asks one thing at a time and has nowhere to go yet).
    if (!sidebar) return <>{children}</>;

    if (TASK_ROUTES.has(routeName)) {
        return <TaskSheet styles={styles}>{children}</TaskSheet>;
    }

    const twoPane = width >= TWO_PANE_MIN_WIDTH;
    const sidebarWidth = twoPane ? SIDEBAR_WIDTH : SIDEBAR_WIDTH_NARROW;
    const rest = width - sidebarWidth;
    const section: Section = routeName === '(tabs)' ? tabSection(pathname) : SECTION_OF[routeName] ?? 'profile';
    const side = <Sidebar active={section} width={sidebarWidth} styles={styles} />;

    // Drive draws its list and the open file itself: one screen, so the
    // attestation it starts with runs once.
    const isList = routeName === '(tabs)' || routeName === 'drive';
    if (isList) {
        if (!twoPane || routeName === 'drive') {
            return (
                <View style={styles.row}>
                    {side}
                    <PaneProvider kind="list" width={rest} twoPane={twoPane}>
                        <View style={styles.fill}>{children}</View>
                    </PaneProvider>
                </View>
            );
        }
        // Nothing open yet: the first column is the wider one, and the
        // second waits for an item.
        const first = emptyListWidth(rest);
        return (
            <View style={styles.row}>
                {side}
                <PaneProvider kind="list" width={first} twoPane={twoPane}>
                    <View style={[styles.list, { width: first }]}>{children}</View>
                </PaneProvider>
                <ChooseItem />
            </View>
        );
    }

    // An item opened from Profile, Access or Settings: beside its screen.
    if (twoPane && section !== 'drive' && SECTION_OF[routeName]) {
        const List = section === 'access' ? AccessScreen : section === 'settings' ? SettingsScreen : ProfileScreen;
        // Two equal columns: a section's own screen reads as well as what it
        // opens. Drive alone narrows its list, for the document's sake.
        const first = openListWidth(rest);
        return (
            <View style={styles.row}>
                {side}
                <PaneProvider kind="list" width={first} twoPane={twoPane}>
                    <View style={[styles.list, { width: first }]}>
                        <List />
                    </View>
                </PaneProvider>
                <PaneProvider
                    kind="detail"
                    width={rest - first}
                    twoPane={twoPane}
                    close={() =>
                        router.canGoBack()
                            ? router.back()
                            : router.replace((section === 'profile' ? '/' : `/${section}`) as never)
                    }
                >
                    <View style={styles.fill}>{children}</View>
                </PaneProvider>
            </View>
        );
    }

    // A screen of its own (anything opened without a section beside it, or
    // any screen in a window too narrow for two columns): one column of
    // readable width. A long page scrolls; it never spills into a second.
    const gutter = columnGutter(rest);
    return (
        <View style={styles.row}>
            {side}
            <PaneProvider kind="page" width={Math.min(rest, READABLE_WIDTH)} twoPane={twoPane}>
                <View style={[styles.fill, { paddingHorizontal: gutter }]}>{children}</View>
            </PaneProvider>
        </View>
    );
}

function Sidebar({ active, width, styles }: { active: Section; width: number; styles: Styles }) {
    const { t } = useTranslation();
    const p = usePalette();
    const router = useRouter();
    const insets = useSafeAreaInsets();
    const profile = useProfileStore((s) => s.profile);
    const waiting = useWaitingCount();
    // Requests for the holder's files, as Profile's Drive row counts them.
    const driveRequests = useDriveNotificationsStore((s) => s.requests.filter((q) => !q.decision).length);

    const go = (s: Section) => {
        // The section open at its top already, or Drive (which opens its files
        // in its own screen): nothing to do.
        if (s === active && (s === 'drive' || !router.canDismiss())) return;
        // Each section starts from its own top: leave whatever was opened.
        if (router.canDismiss()) router.dismissAll();
        if (s === 'drive') router.push('/drive');
        else router.navigate(s === 'profile' ? '/' : (`/${s}` as never));
    };

    const items: { key: Section; icon: keyof typeof Ionicons.glyphMap; label: string; badge?: number }[] = [
        { key: 'profile', icon: 'person-circle', label: t('tabs.profile') },
        { key: 'drive', icon: 'folder', label: t('tabs.drive'), badge: driveRequests },
        { key: 'access', icon: 'key', label: t('tabs.access'), badge: waiting },
        { key: 'settings', icon: 'settings', label: t('tabs.settings') },
    ];

    return (
        <View style={[styles.sidebar, { width, paddingTop: insets.top + 24, paddingBottom: insets.bottom + 24 }]}>
            {profile && (
                <View style={styles.who}>
                    {profile.avatarUri ? (
                        <Image source={{ uri: profile.avatarUri }} style={styles.avatar} />
                    ) : (
                        <View style={[styles.avatar, styles.avatarEmpty]}>
                            <Ionicons name="person" size={20} color={p.textMuted} />
                        </View>
                    )}
                    <View style={styles.fill}>
                        <Text style={styles.whoName} numberOfLines={1}>
                            {profileDisplayName(profile, t('profile.defaultDisplayName'))}
                        </Text>
                        {!!primaryEmail(profile) && (
                            <Text style={styles.whoSub} numberOfLines={1}>
                                {primaryEmail(profile)}
                            </Text>
                        )}
                    </View>
                </View>
            )}
            {items.map((it) => {
                const on = it.key === active;
                return (
                    <Pressable
                        key={it.key}
                        // The tab bar's ids: the same flows drive both layouts.
                        testID={`tab-${it.key}`}
                        onPress={() => go(it.key)}
                        style={[styles.item, on && styles.itemOn]}
                        accessibilityRole="tab"
                        accessibilityState={{ selected: on }}
                    >
                        <Ionicons name={it.icon} size={22} color={on ? p.action : p.textMuted} />
                        <Text style={[styles.itemLabel, on && styles.itemLabelOn]}>{it.label}</Text>
                        {!!it.badge && (
                            <View style={styles.badge}>
                                <Text style={styles.badgeText}>{it.badge > 99 ? '99+' : String(it.badge)}</Text>
                            </View>
                        )}
                    </Pressable>
                );
            })}
            <View style={styles.fill} />
            <Pressable
                style={styles.scan}
                onPress={() => router.push('/scan')}
                accessibilityLabel={t('home.scanQrCode')}
                testID="side-scan"
            >
                <Ionicons name="qr-code-outline" size={20} color="#FFFFFF" />
                <Text style={styles.scanText}>{t('home.scanQrCode')}</Text>
            </Pressable>
        </View>
    );
}

/** What the second column shows with nothing open in it. */
export function ChooseItem() {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    return (
        <View style={[styles.fill, styles.choose]}>
            <Ionicons name="albums-outline" size={40} color={p.textMuted} />
            <Text style={styles.chooseText}>{t('tabs.chooseItem')}</Text>
        </View>
    );
}

/** A task: a sheet in the middle of the window, over everything else. */
function TaskSheet({ children, styles }: { children: ReactNode; styles: Styles }) {
    const { width, height } = useWindowDimensions();
    const insets = useSafeAreaInsets();
    const sheetWidth = Math.min(SHEET_WIDTH, width - 64);
    const margin = Math.max(insets.top, 24) + 24;
    // As tall as most tasks need, not the whole window: a short request does
    // not sit in a sheet of empty space, and a longer task scrolls in it.
    const sheetHeight = Math.min(height - margin * 2, SHEET_MAX_HEIGHT);
    return (
        <View style={styles.backdrop}>
            <View style={[styles.sheet, { width: sheetWidth, height: sheetHeight }]}>
                {/* The sheet sits clear of the status bar and the home
                    indicator, so the screen inside needs no room for them. */}
                <SafeAreaInsetsContext.Provider value={NO_INSETS}>
                    <PaneProvider kind="task" width={sheetWidth} twoPane={false}>
                        {children}
                    </PaneProvider>
                </SafeAreaInsetsContext.Provider>
            </View>
        </View>
    );
}

type Styles = ReturnType<typeof makeStyles>;

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        row: { flex: 1, flexDirection: 'row', backgroundColor: p.screenBg },
        fill: { flex: 1, minWidth: 0 },
        list: { borderRightWidth: StyleSheet.hairlineWidth, borderRightColor: p.border },
        sidebar: {
            paddingHorizontal: 16,
            gap: 6,
            backgroundColor: p.card,
            borderRightWidth: StyleSheet.hairlineWidth,
            borderRightColor: p.border,
        },
        who: { flexDirection: 'row', alignItems: 'center', gap: 12, paddingHorizontal: 12, paddingBottom: 20 },
        avatar: { width: 40, height: 40, borderRadius: 20 },
        avatarEmpty: { backgroundColor: p.screenBg, alignItems: 'center', justifyContent: 'center' },
        whoName: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
        whoSub: { fontSize: 13, color: p.textSecondary },
        item: {
            flexDirection: 'row',
            alignItems: 'center',
            gap: 12,
            paddingHorizontal: 12,
            minHeight: 46,
            borderRadius: 12,
        },
        // The action blue at 8%: the chosen section, in either theme.
        itemOn: { backgroundColor: `${p.action}14` },
        itemLabel: { flex: 1, fontSize: 16, fontWeight: '500', color: p.textPrimary },
        itemLabelOn: { fontWeight: '600', color: p.action },
        badge: {
            minWidth: 22,
            height: 22,
            borderRadius: 11,
            paddingHorizontal: 6,
            backgroundColor: p.danger,
            alignItems: 'center',
            justifyContent: 'center',
        },
        badgeText: { color: '#FFFFFF', fontSize: 12, fontWeight: '700' },
        scan: {
            flexDirection: 'row',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 10,
            height: 48,
            borderRadius: 12,
            backgroundColor: p.action,
        },
        scanText: { color: '#FFFFFF', fontSize: 15, fontWeight: '600' },
        choose: { alignItems: 'center', justifyContent: 'center', gap: 12, padding: 32 },
        chooseText: { fontSize: 16, color: p.textSecondary, textAlign: 'center' },
        backdrop: {
            flex: 1,
            backgroundColor: 'rgba(15,23,42,0.45)',
            alignItems: 'center',
            justifyContent: 'center',
        },
        sheet: { borderRadius: 22, overflow: 'hidden', backgroundColor: p.screenBg },
    });
