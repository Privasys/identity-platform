// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The logo is the lock (services/app-lock). The wallet opens on the logo's two
 * halves, closed, the green over the blue with a white gap between them. They
 * slide apart onto the wallet:
 *
 * - at start, straight away when the lock is off, or once Face ID succeeds;
 * - on coming back after the chosen time, once Face ID succeeds again.
 *
 * Face ID is asked for by itself, over the closed halves. If the holder
 * cancels it, Unlock waits at the bottom, clear of where iOS draws Face ID.
 *
 * While the wallet is away (in the app switcher, under Control Centre) the
 * halves close as a cover, so the switcher's preview shows the logo rather
 * than the screen that was open. They go without a slide when the wallet comes
 * back unlocked.
 *
 * JavaScript draws a frame or two late for the snapshot iOS takes as the app
 * goes to the background, so a native cover (modules/privacy-cover) is added
 * in that moment, the same closed halves, and lifted once this screen has
 * caught up on return.
 *
 * A request screen that needs its own Face ID (services/app-lock lockExempt)
 * opens without the unlock.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import * as LocalAuthentication from 'expo-local-authentication';
import { usePathname } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
    AppState,
    Platform,
    Pressable,
    StyleSheet,
    View as RNView,
    useWindowDimensions,
    type AppStateStatus,
} from 'react-native';
import Animated, { Easing, cancelAnimation, runOnJS, useAnimatedStyle, useSharedValue, withTiming } from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import * as PrivacyCover from '../../modules/privacy-cover/src/index';
import { taskStyles } from '@/components/task-styles';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { locksOnReturn, lockExempt, promptOpen, withPrompt } from '@/services/app-lock';
import { isDemo } from '@/services/demo/gate';
import { useAppLockStore } from '@/stores/app-lock';
import { useProfileStore } from '@/stores/profile';
import { useSettingsStore } from '@/stores/settings';

/** The app icon's colours, which the halves are. */
const LOGO_GREEN = '#34C17B';
const LOGO_BLUE = '#00AAEE';
const LOGO_GROUND = '#FFFFFF';
const LOGO_INK = '#0F172A';
/** The white gap between the halves. */
const GAP = 20;
const OPEN_MS = 450;
const CLOSE_MS = 300;
/** The longest the lock waits for a tapped push to open its screen. */
const PUSH_WAIT_MS = 4000;
/** On a return, how long the lock lets a tapped push land before asking. */
const RETURN_WAIT_MS = 350;

/** Ask for Face ID to open the wallet. True once the holder is verified. */
export async function unlockWallet(prompt: string, cancel: string, beforeUnlock?: () => void): Promise<boolean> {
    const r = await withPrompt(() => LocalAuthentication.authenticateAsync({ promptMessage: prompt, cancelLabel: cancel }));
    if (r.success) {
        beforeUnlock?.();
        useAppLockStore.getState().unlock();
    }
    return r.success;
}

type Mode = 'shut' | 'closing' | 'opening' | 'gone';

export function AppLock({ onShown, onOpened }: { onShown?: () => void; onOpened?: () => void }) {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const pathname = usePathname();
    const insets = useSafeAreaInsets();
    const { width: W, height: H } = useWindowDimensions();

    const hasProfile = useProfileStore((s) => s.profile != null);
    const lockSec = useSettingsStore((s) => s.appLockSec);
    const locked = useAppLockStore((s) => s.locked);
    const exemptPushAt = useAppLockStore((s) => s.exemptPushAt);
    const launchPushChecked = useAppLockStore((s) => s.launchPushChecked);
    const on = !isDemo() && hasProfile && lockSec != null;

    const [appState, setAppState] = useState<AppStateStatus>(AppState.currentState);
    const [busy, setBusy] = useState(false);
    // Face ID was cancelled or failed: Unlock shows.
    const [failed, setFailed] = useState(false);
    // Face ID has just succeeded: the lock in the gap shows open for a moment
    // before the halves slide apart.
    const [openLock, setOpenLock] = useState(false);

    // The halves start closed. With the lock on, the start is a lock.
    const [launching, setLaunching] = useState(true);
    useEffect(() => {
        if (on) useAppLockStore.getState().lock();
        setLaunching(false);
        // Once, at start.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // Away and back: locked again once the chosen time has passed.
    useEffect(() => {
        const sub = AppState.addEventListener('change', (next) => {
            setAppState(next);
            const store = useAppLockStore.getState();
            if (next === 'background') store.wentToBackground(Date.now());
            if (next === 'active') {
                const { appLockSec } = useSettingsStore.getState();
                if (on && locksOnReturn(appLockSec, store.backgroundAt, Date.now())) store.lock();
                store.wentToBackground(null);
            }
        });
        return () => sub.remove();
    }, [on]);

    // The native cover follows the lock, and is lifted once this screen has
    // drawn what the return calls for: the lock, or the wallet.
    useEffect(() => {
        PrivacyCover.setEnabled(on);
    }, [on]);
    useEffect(() => {
        if (appState !== 'active') return;
        // Two frames: the one that draws it, and the one that shows it.
        let frame = requestAnimationFrame(() => {
            frame = requestAnimationFrame(() => PrivacyCover.release());
        });
        return () => cancelAnimationFrame(frame);
    }, [appState]);

    const showLock = on && locked && !lockExempt(pathname);
    // iOS draws the switcher's preview just after the app goes inactive;
    // Android once it is in the background. Not while a Face ID prompt of the
    // wallet's own makes it inactive.
    const away =
        Platform.OS === 'ios'
            ? (appState === 'inactive' || appState === 'background') && !promptOpen()
            : appState === 'background';
    const cover = on && away;
    const shut = launching || showLock || cover;

    // Opening slides, after a start or an unlock; a cover over an unlocked
    // wallet just goes. Closing slides too when the holder is watching (leaving
    // an approval screen without approving), and is instant at start or while
    // the wallet is out of sight.
    const progress = useSharedValue(0);
    const [mode, setMode] = useState<Mode>('shut');
    const slideNext = useRef(true);
    const opened = useRef(false);
    const finishOpen = useCallback(() => {
        setMode('gone');
        setOpenLock(false);
        slideNext.current = false;
        if (!opened.current) {
            opened.current = true;
            onOpened?.();
        }
    }, [onOpened]);
    useEffect(() => {
        if (shut) {
            cancelAnimation(progress);
            if (launching || showLock) slideNext.current = true;
            if (!launching && !cover && appState === 'active' && mode !== 'shut') {
                setMode('closing');
                progress.value = withTiming(0, { duration: CLOSE_MS, easing: Easing.out(Easing.cubic) }, (done) => {
                    if (done) runOnJS(setMode)('shut');
                });
                return;
            }
            progress.value = 0;
            setMode('shut');
            return;
        }
        if (mode !== 'shut' && mode !== 'closing') return;
        cancelAnimation(progress);
        if (!slideNext.current) {
            setMode('gone');
            return;
        }
        // No wait after Face ID: the halves part at once, and the lock in the
        // gap, open by then, fades as they go.
        setMode('opening');
        progress.value = withTiming(1, { duration: OPEN_MS, easing: Easing.in(Easing.cubic) }, (done) => {
            if (done) runOnJS(finishOpen)();
        });
        // `mode` is read, not followed: the effect answers `shut` changing.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [shut, launching, showLock]);

    useEffect(() => {
        if (!showLock) setFailed(false);
        else setOpenLock(false);
    }, [showLock]);

    // A tapped approval push is on its way to its screen: the lock waits for
    // it rather than asking for Face ID, then lets it open. If the screen
    // never comes, the lock asks after all.
    const exempt = lockExempt(pathname);
    useEffect(() => {
        if (exemptPushAt == null) return;
        const { clearExemptPush } = useAppLockStore.getState();
        if (exempt) {
            clearExemptPush();
            return;
        }
        const timer = setTimeout(clearExemptPush, Math.max(0, exemptPushAt + PUSH_WAIT_MS - Date.now()));
        return () => clearTimeout(timer);
    }, [exemptPushAt, exempt]);
    // At start, the push that launched the wallet is looked for first. Should
    // that never answer, the lock asks anyway.
    const [launchWaitOver, setLaunchWaitOver] = useState(false);
    useEffect(() => {
        const timer = setTimeout(() => setLaunchWaitOver(true), PUSH_WAIT_MS);
        return () => clearTimeout(timer);
    }, []);
    const pushWaiting = exemptPushAt != null || !(launchPushChecked || launchWaitOver);

    const unlock = useCallback(async () => {
        if (busy) return;
        setBusy(true);
        try {
            const ok = await unlockWallet(t('appLock.prompt'), t('common.cancel'), () => {
                // Set with the unlock, so the lock is open as the halves part.
                setOpenLock(true);
            });
            setFailed(!ok);
        } finally {
            setBusy(false);
        }
    }, [busy, t]);

    // Ask once by itself each time the lock appears in front of the holder. On
    // a return, a short wait lets a tapped push that opens a request screen
    // land first (its response comes just after the app turns active). At
    // start there is no wait: the launch push has been read and marked before
    // pushWaiting clears (services/push-router, setLaunchPushChecked).
    const asked = useRef(false);
    const firstAsk = useRef(true);
    useEffect(() => {
        if (!showLock) {
            asked.current = false;
            return;
        }
        if (asked.current || appState !== 'active' || pushWaiting) return;
        const ask = () => {
            asked.current = true;
            firstAsk.current = false;
            void unlock();
        };
        if (firstAsk.current) {
            ask();
            return;
        }
        const timer = setTimeout(ask, RETURN_WAIT_MS);
        return () => clearTimeout(timer);
    }, [showLock, appState, pushWaiting, unlock]);

    // Two squares turned 45°, much larger than the screen, each with an edge
    // GAP/2 from the diagonal through the centre.
    const size = Math.max(W, H) * 1.5;
    const offset = ((size + GAP) * Math.SQRT2) / 4;
    const greenStyle = useAnimatedStyle(() => ({
        transform: [{ translateY: -progress.value * H }, { rotate: '-45deg' }],
    }));
    const blueStyle = useAnimatedStyle(() => ({
        transform: [{ translateY: progress.value * H }, { rotate: '-45deg' }],
    }));
    // The lock fades in the first part of the slide.
    const lockStyle = useAnimatedStyle(() => ({ opacity: Math.max(0, 1 - progress.value * 3) }));

    const shown = useRef(false);
    if (mode === 'gone') return null;
    const closed = mode === 'shut';
    return (
        <RNView
            style={[StyleSheet.absoluteFill, styles.screen, closed && styles.ground]}
            pointerEvents={mode === 'opening' ? 'none' : 'auto'}
            accessibilityViewIsModal={closed}
            testID="app-lock"
            onLayout={() => {
                if (shown.current) return;
                shown.current = true;
                onShown?.();
            }}
        >
            <Animated.View
                style={[
                    styles.half,
                    { width: size, height: size, top: H / 2 - offset - size / 2, left: W / 2 - offset - size / 2, backgroundColor: LOGO_GREEN },
                    greenStyle,
                ]}
            />
            <Animated.View
                style={[
                    styles.half,
                    { width: size, height: size, top: H / 2 + offset - size / 2, left: W / 2 + offset - size / 2, backgroundColor: LOGO_BLUE },
                    blueStyle,
                ]}
            />
            {/* The lock sits in the gap while the wallet is locked. */}
            {(closed && on && (locked || cover)) || (openLock && mode === 'opening') ? (
                <Animated.View
                    style={[styles.gapLock, { top: H / 2 - GAP_LOCK / 2, left: W / 2 - GAP_LOCK / 2 }, lockStyle]}
                    pointerEvents="none"
                >
                    <Ionicons name={openLock && !locked ? 'lock-open' : 'lock-closed'} size={18} color={LOGO_INK} />
                </Animated.View>
            ) : null}
            {closed && showLock && failed && !cover ? (
                <RNView style={[styles.bottom, { paddingBottom: insets.bottom + 24 }]}>
                    <Pressable
                        style={[styles.affirmButton, styles.unlock, busy && styles.buttonIdle]}
                        disabled={busy}
                        onPress={() => void unlock()}
                        accessibilityRole="button"
                        testID="app-lock-unlock"
                    >
                        <Text style={[styles.affirmButtonText, styles.unlockText]}>{t('appLock.unlock')}</Text>
                    </Pressable>
                </RNView>
            ) : null}
        </RNView>
    );
}

const GAP_LOCK = 44;

const makeStyles = (p: Palette) => ({
    ...taskStyles(p),
    ...StyleSheet.create({
        screen: { zIndex: 1000, elevation: 1000, overflow: 'hidden' },
        ground: { backgroundColor: LOGO_GROUND },
        half: { position: 'absolute' },
        gapLock: {
            position: 'absolute',
            width: GAP_LOCK,
            height: GAP_LOCK,
            borderRadius: GAP_LOCK / 2,
            backgroundColor: LOGO_GROUND,
            alignItems: 'center',
            justifyContent: 'center',
        },
        bottom: { position: 'absolute', left: 24, right: 24, bottom: 0 },
        unlock: { flex: 0, alignSelf: 'stretch', backgroundColor: LOGO_GROUND },
        unlockText: { color: LOGO_INK },
    }),
});
