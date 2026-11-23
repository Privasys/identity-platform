// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Loading a list the holder waits on from privasys.id (app messages, access
 * requests), one load at a time.
 *
 * In the background a list is read only with a platform token the wallet
 * already holds, so opening a tab never puts a Face ID sheet in front of
 * anyone. A list that cannot be read says so (`loadFailed`), rather than
 * looking like "nothing waiting"; the holder's Try again loads it
 * interactively, which may mint a token.
 */

/**
 * Wrap a list load so loads never overlap. A background refresh joins one
 * already running. An interactive one (the holder tapped Try again) waits for
 * it, then runs its own, since the running one may be the background load that
 * just failed.
 */
export function oneLoadAtATime(
    load: (interactive: boolean) => Promise<void>,
): (opts?: { interactive?: boolean }) => Promise<void> {
    let inflight: Promise<void> | null = null;
    return (opts) => {
        const interactive = !!opts?.interactive;
        if (inflight && !interactive) return inflight;
        const before = inflight ?? Promise.resolve();
        const p: Promise<void> = before
            .then(() => load(interactive))
            .finally(() => {
                if (inflight === p) inflight = null;
            });
        inflight = p;
        return p;
    };
}
