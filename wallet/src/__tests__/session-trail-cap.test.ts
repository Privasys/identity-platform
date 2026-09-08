// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The per-app cap on the session trail.
 *
 * The global cap of 400 stops the store growing without bound but does nothing
 * for a single app: one service reached 33 entries, in a card the holder has to
 * scroll past to reach anything below it, and a busy app could crowd every
 * other app out of the global budget entirely.
 */

jest.mock('@/utils/storage', () => {
    const store: Record<string, string> = {};
    return {
        getItemAsync: jest.fn(async (k: string) => store[k] ?? null),
        setItemAsync: jest.fn(async (k: string, v: string) => { store[k] = v; }),
        deleteItemAsync: jest.fn(async (k: string) => { delete store[k]; }),
    };
});

import { useServiceSessionsStore } from '@/stores/service-sessions';

const trace = (serviceKey: string, kind = 'sign-in') => ({
    serviceKey,
    kind,
    at: Math.floor(Date.now() / 1000),
}) as never;

beforeEach(() => {
    useServiceSessionsStore.setState({ traces: [] });
});

describe('the per-app session trail', () => {
    it('keeps only the ten most recent for one app', () => {
        const store = useServiceSessionsStore.getState();
        for (let i = 0; i < 33; i++) store.record(trace('harness', `ceremony-${i}`));

        const kept = useServiceSessionsStore.getState().traces.filter((t) => t.serviceKey === 'harness');
        expect(kept).toHaveLength(10);
    });

    it('keeps the NEWEST ten, not the oldest', () => {
        const store = useServiceSessionsStore.getState();
        for (let i = 0; i < 15; i++) store.record(trace('harness', `ceremony-${i}`));

        const kinds = useServiceSessionsStore.getState().traces.map((t) => t.kind);
        // Newest first, so the most recent ceremony leads and the first five are gone.
        expect(kinds[0]).toBe('ceremony-14');
        expect(kinds).not.toContain('ceremony-4');
        expect(kinds).toContain('ceremony-5');
    });

    // The point of a PER-APP cap: one busy app must not evict another app's
    // history, which is exactly what a single global budget allows.
    it('does not let a busy app crowd out a quiet one', () => {
        const store = useServiceSessionsStore.getState();
        store.record(trace('drive', 'the-only-drive-ceremony'));
        for (let i = 0; i < 40; i++) store.record(trace('harness', `ceremony-${i}`));

        const traces = useServiceSessionsStore.getState().traces;
        expect(traces.filter((t) => t.serviceKey === 'harness')).toHaveLength(10);
        expect(traces.filter((t) => t.serviceKey === 'drive')).toHaveLength(1);
    });

    it('leaves an app under the cap untouched', () => {
        const store = useServiceSessionsStore.getState();
        for (let i = 0; i < 3; i++) store.record(trace('drive', `ceremony-${i}`));
        expect(useServiceSessionsStore.getState().traces).toHaveLength(3);
    });
});
