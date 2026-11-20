// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The app lock's screen (services/app-lock), drawn above everything.
 *
 * - Locked: the wallet asks for Face ID by itself, then offers Unlock if the
 *   holder cancelled. The phone's passcode is accepted where Face ID fails.
 * - Away (in the app switcher, under Control Centre): a plain cover, so the
 *   switcher's preview does not show the screen that was open.
 *
 * Both only while the lock is on. A request screen that needs its own Face ID
 * (services/app-lock lockExempt) opens without the unlock.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import * as LocalAuthentication from 'expo-local-authentication';
import { usePathname } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AppState, Platform, Pressable, StyleSheet, View as RNView, type AppStateStatus } from 'react-native';
import { useTranslation } from 'react-i18next';

import { taskStyles } from '@/components/task-styles';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { locksOnReturn, lockExempt, promptOpen, withPrompt } from '@/services/app-lock';
import { isDemo } from '@/services/demo/gate';
import { useAppLockStore } from '@/stores/app-lock';
import { useProfileStore } from '@/stores/profile';
import { useSettingsStore } from '@/stores/settings';

/** Ask for Face ID to open the wallet. True once the holder is verified. */
export async function unlockWallet(prompt: string, cancel: string): Promise<boolean> {
    const r = await withPrompt(() => LocalAuthentication.authenticateAsync({ promptMessage: prompt, cancelLabel: cancel }));
    if (r.success) useAppLockStore.getState().unlock();
    return r.success;
}

export function AppLock({ ready }: { ready: boolean }) {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const pathname = usePathname();

    const hasProfile = useProfileStore((s) => s.profile != null);
    const lockSec = useSettingsStore((s) => s.appLockSec);
    const locked = useAppLockStore((s) => s.locked);
    const on = !isDemo() && hasProfile && lockSec != null;

    const [appState, setAppState] = useState<AppStateStatus>(AppState.currentState);
    const [busy, setBusy] = useState(false);

    // A start with the lock on begins locked.
    const started = useRef(false);
    useEffect(() => {
        if (started.current || !ready) return;
        started.current = true;
        if (on) useAppLockStore.getState().lock();
    }, [on, ready]);

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

    const exempt = lockExempt(pathname);
    const showLock = on && ready && locked && !exempt;

    const unlock = useCallback(async () => {
        if (busy) return;
        setBusy(true);
        try {
            await unlockWallet(t('appLock.prompt'), t('common.cancel'));
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

    // iOS draws the switcher's preview just after the app goes inactive; Android
    // once it is in the background.
    const away =
        Platform.OS === 'ios'
            ? (appState === 'inactive' || appState === 'background') && !promptOpen()
            : appState === 'background';
    const showCover = on && away;

    if (!showLock && !showCover) return null;
    return (
        <RNView style={[StyleSheet.absoluteFill, styles.screen]} testID="app-lock">
            <RNView style={styles.centre}>
                <RNView style={styles.badge}>
                    <Ionicons name="lock-closed" size={30} color={p.green} />
                </RNView>
                {/* The cover says nothing: it may only be the app switcher. */}
                {showLock && !showCover ? <Text style={styles.lockTitle}>{t('appLock.lockedTitle')}</Text> : null}
                {showLock && !showCover ? (
                    <Pressable
                        style={[styles.affirmButton, styles.unlock, busy && styles.buttonIdle]}
                        disabled={busy}
                        onPress={() => void unlock()}
                        accessibilityRole="button"
                        testID="app-lock-unlock"
                    >
                        <Text style={styles.affirmButtonText}>{t('appLock.unlock')}</Text>
                    </Pressable>
                ) : null}
            </RNView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => ({
    ...taskStyles(p),
    ...StyleSheet.create({
        screen: { backgroundColor: p.screenBg, zIndex: 1000, elevation: 1000 },
        centre: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 32, gap: 16 },
        badge: {
            width: 64,
            height: 64,
            borderRadius: 32,
            backgroundColor: p.card,
            alignItems: 'center',
            justifyContent: 'center',
        },
        lockTitle: { fontSize: 17, fontWeight: '600', color: p.textPrimary, textAlign: 'center' },
        unlock: { flex: 0, alignSelf: 'stretch', marginTop: 8 },
    }),
});
