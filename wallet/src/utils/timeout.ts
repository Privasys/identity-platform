// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Bound a promise that has no business hanging forever.
 *
 * Written for the native prompts the setup ceremony drives. A biometric prompt
 * that never settles takes the whole ceremony with it: the spinner belongs to
 * the awaiting function, so the screen stays busy and the only way out is to
 * force-quit the app (reported on iOS, 2026-08-26). Rejecting instead turns a
 * wedged prompt into an error the user can dismiss and retry.
 *
 * The underlying work is NOT cancelled — nothing here can cancel a native
 * dialog. It is abandoned: a late resolution is ignored, and the timer is
 * cleared either way so the timeout cannot outlive the call.
 */
export function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout>;
    return Promise.race([
        promise,
        new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
        }),
    ]).finally(() => clearTimeout(timer)) as Promise<T>;
}

/**
 * How long to wait on a device-unlock prompt before giving up.
 *
 * Generous on purpose: the user may be finding a finger, retrying a failed
 * face match, or falling back to a passcode. This is a deadlock breaker, not a
 * usability deadline.
 */
export const BIOMETRIC_TIMEOUT_MS = 120_000;
