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

/** Ask for Face ID to open the wallet. True once the holder is verified. */
export async function unlockWallet(prompt: string, cancel: string): Promise<boolean> {
    const r = await withPrompt(() => LocalAuthentication.authenticateAsync({ promptMessage: prompt, cancelLabel: cancel }));
    if (r.success) useAppLockStore.getState().unlock();
    return r.success;
}

type Mode = 'shut' | 'opening' | 'gone';

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
    const on = !isDemo() && hasProfile && lockSec != null;

    const [appState, setAppState] = useState<AppStateStatus>(AppState.currentState);
    const [busy, setBusy] = useState(false);
    // Face ID was cancelled or failed: Unlock shows.
    const [failed, setFailed] = useState(false);

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

    // Closing is instant: it happens at start, or while the wallet is out of
    // sight. Opening slides, after a start or an unlock; a cover over an
    // unlocked wallet just goes.
    const progress = useSharedValue(0);
    const [mode, setMode] = useState<Mode>('shut');
    const slideNext = useRef(true);
    const opened = useRef(false);
    const finishOpen = useCallback(() => {
        setMode('gone');
        slideNext.current = false;
        if (!opened.current) {
            opened.current = true;
            onOpened?.();
        }
    }, [onOpened]);
    useEffect(() => {
        if (shut) {
            cancelAnimation(progress);
            progress.value = 0;
            if (launching || showLock) slideNext.current = true;
            setMode('shut');
            return;
        }
        if (mode !== 'shut') return;
        if (!slideNext.current) {
            setMode('gone');
            return;
        }
        setMode('opening');
        progress.value = withTiming(1, { duration: OPEN_MS, easing: Easing.in(Easing.cubic) }, (done) => {
            if (done) runOnJS(finishOpen)();
        });
        // `mode` is read, not followed: the effect answers `shut` changing.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [shut, launching, showLock]);

    useEffect(() => {
        if (!showLock) setFailed(false);
    }, [showLock]);

    const unlock = useCallback(async () => {
        if (busy) return;
        setBusy(true);
        try {
            const ok = await unlockWallet(t('appLock.prompt'), t('common.cancel'));
            setFailed(!ok);
        } finally {
            setBusy(false);
        }
    }, [busy, t]);

    // Ask once by itself each time the lock appears in front of the holder; a
    // short wait lets a push that opens a request screen land first.
    const asked = useRef(false);
    useEffect(() => {
        if (!showLock) {
            asked.current = false;
            return;
        }
        if (asked.current || appState !== 'active') return;
        const timer = setTimeout(() => {
            asked.current = true;
            void unlock();
        }, 350);
        return () => clearTimeout(timer);
    }, [showLock, appState, unlock]);

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

    const shown = useRef(false);
    if (mode === 'gone') return null;
    const closed = mode === 'shut';
    return (
        <RNView
            style={[StyleSheet.absoluteFill, styles.screen, closed && styles.ground]}
            pointerEvents={closed ? 'auto' : 'none'}
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
            {closed && on && (locked || cover) ? (
                <RNView style={[styles.gapLock, { top: H / 2 - GAP_LOCK / 2, left: W / 2 - GAP_LOCK / 2 }]} pointerEvents="none">
                    <Ionicons name="lock-closed" size={18} color={LOGO_INK} />
                </RNView>
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
