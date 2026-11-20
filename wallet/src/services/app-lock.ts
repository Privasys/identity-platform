// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The app lock: Face ID (or the phone's passcode) before the wallet shows
 * anything, on every start and on coming back after the time the holder chose.
 *
 * It guards against one thing: someone holding the phone while it is unlocked.
 * It encrypts nothing (the phone's own storage already does that), so no copy
 * may say it does.
 *
 * The holder is asked once, after setup or on the first start of a version
 * that has the lock, and changes it in Settings. The demo build has neither
 * the question nor the lock, so the screenshot flows run as before.
 */

/** Seconds away before the wallet locks again. 0 locks on every return. */
export const APP_LOCK_OPTIONS = [0, 60, 300] as const;
export type AppLockSeconds = (typeof APP_LOCK_OPTIONS)[number];

/** What turning the lock on from the question chooses. */
export const APP_LOCK_DEFAULT: AppLockSeconds = 60;

export function isAppLockSeconds(v: unknown): v is AppLockSeconds {
    return typeof v === 'number' && (APP_LOCK_OPTIONS as readonly number[]).includes(v);
}

/**
 * Screens that open without the unlock. Each shows only a request and does
 * nothing without its own fresh Face ID, so asking first would make the holder
 * look twice for one answer. Leaving one for anywhere else meets the lock.
 */
const EXEMPT = ['/vault-approvals', '/approval'];

export function lockExempt(pathname: string): boolean {
    return EXEMPT.some((p) => pathname === p || pathname.startsWith(p + '?') || pathname.startsWith(p + '/'));
}

/** Whether coming back to the wallet locks it. */
export function locksOnReturn(lockSec: AppLockSeconds | null, backgroundAt: number | null, now: number): boolean {
    if (lockSec == null || backgroundAt == null) return false;
    return now - backgroundAt >= lockSec * 1000;
}

/** The tabs, where the one-time question may interrupt: never a task. */
export function isTabPath(pathname: string): boolean {
    return pathname === '/' || pathname === '/access' || pathname === '/settings';
}

/*
 * Face ID prompts the wallet itself opens. On iOS a prompt makes the app
 * inactive, which is also the moment the app-switcher cover goes up; while one
 * of these is open the cover stays down, so the holder still sees what they
 * are approving behind the prompt.
 */
let prompts = 0;

export function promptOpen(): boolean {
    return prompts > 0;
}

/** Run a biometric prompt the wallet opens, holding the cover down meanwhile. */
export async function withPrompt<T>(prompt: () => Promise<T>): Promise<T> {
    prompts++;
    try {
        return await prompt();
    } finally {
        prompts--;
    }
}
