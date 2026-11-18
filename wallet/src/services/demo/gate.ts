// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The demo mode gate: the only module the rest of the wallet imports to ask
 * whether this is the demo build, and the only path to the fixtures.
 *
 * `EXPO_PUBLIC_DEMO` is inlined by Babel at build time. In a release build
 * Metro then folds `undefined === '1'` (or `'0' === '1'`) to false and drops
 * the branch BEFORE it collects dependencies, so the `require('./api')` below
 * is never seen and no fixture, sample file or portrait reaches a normal
 * bundle. That only works while the comparison is written out literally in
 * each function here: a constant computed once and imported elsewhere would
 * not be folded.
 */

import type * as DemoApi from './api';

/** True only in a build made with EXPO_PUBLIC_DEMO=1 (the `demo` profile). */
export function isDemo(): boolean {
    return process.env.EXPO_PUBLIC_DEMO === '1';
}

/**
 * The demo fixtures and stand-ins. Loaded on first use, and only reachable in
 * a demo build: anywhere else this throws rather than hand back made-up data.
 */
export function demo(): typeof DemoApi {
    if (process.env.EXPO_PUBLIC_DEMO === '1') {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        return require('./api') as typeof DemoApi;
    }
    throw new Error('demo fixtures are not part of this build');
}

/**
 * Refuse to start a demo on a production stage. The demo has its own bundle
 * id, so it cannot replace a real install, but a production build that also
 * carried EXPO_PUBLIC_DEMO=1 would show invented data to a real holder. That
 * is a build mistake, and it should stop the app at launch rather than ship.
 */
export function assertDemoAllowed(stage: unknown): void {
    if (isDemo() && stage === 'production') {
        throw new Error('Demo mode is on in a production build. Build the demo with the `demo` profile.');
    }
}
