// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The loop that crashed Service Details on iPad in 1.4.77 ("Maximum update
 * depth exceeded"): the wide frame redraws when a screen sets its navigation
 * options, and a screen that reads its pane re-renders on every redraw that
 * hands it a new value, sets its options again, and so on. The pane must keep
 * its value while nothing about it changes.
 */

jest.mock('@/components/Themed', () => ({ usePalette: () => ({ action: '#007AFF' }) }));
jest.mock('@/hooks/useLargeScreen', () => ({ useLargeScreen: () => true }));

import { createContext, createElement as h, useContext, useLayoutEffect, useState, type ReactNode } from 'react';
import TestRenderer, { act } from 'react-test-renderer';

import { PaneContext, usePane, type Pane } from '@/components/pane';
import { PaneProvider } from '@/components/PaneProvider';

/** What a navigator gives a screen: a way to set its options, which redraws the frame. */
const SetOptions = createContext<(o: object) => void>(() => undefined);

/** The frame, as WideFrame draws it: it redraws whenever options are set. */
function Frame({ stable, children }: { stable: boolean; children: ReactNode }) {
    const [, setOptions] = useState<object>({});
    const pane = stable
        ? h(PaneProvider, { kind: 'detail', width: 500, twoPane: true, close: () => undefined }, children)
        : // The 1.4.77 frame: a fresh value on every draw.
          h(PaneContext.Provider, { value: { kind: 'detail', width: 500, twoPane: true, close: () => undefined } }, children);
    return h(SetOptions.Provider, { value: setOptions }, pane);
}

let renders = 0;
let seen: (Pane | null)[] = [];

/** A screen that reads its pane, and sets its options as it renders (a Stack.Screen). */
function Screen() {
    const pane = usePane();
    const setOptions = useContext(SetOptions);
    renders++;
    seen.push(pane);
    // As Stack.Screen sets its options: in a layout effect.
    useLayoutEffect(() => {
        setOptions({ headerShown: false });
    });
    return null;
}

beforeEach(() => {
    renders = 0;
    seen = [];
});

describe('PaneProvider', () => {
    it('keeps a screen that sets its options from looping', () => {
        act(() => {
            TestRenderer.create(h(Frame, { stable: true }, h(Screen)));
        });
        expect(renders).toBe(1);
    });

    it('is what stops the loop: a fresh value each draw loops, as in 1.4.77', () => {
        const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);
        expect(() =>
            act(() => {
                TestRenderer.create(h(Frame, { stable: false }, h(Screen)));
            }),
        ).toThrow(/Maximum update depth exceeded/);
        error.mockRestore();
    });

    it('keeps the same value while its props are the same, and calls the latest close', () => {
        const calls: string[] = [];
        const Host = ({ tag }: { tag: string }) =>
            h(PaneProvider, { kind: 'list', width: 400, twoPane: true, close: () => calls.push(tag) }, h(Screen));
        let r: TestRenderer.ReactTestRenderer | undefined;
        act(() => {
            r = TestRenderer.create(h(Host, { tag: 'a' }));
        });
        act(() => {
            r!.update(h(Host, { tag: 'b' }));
        });
        expect(seen.length).toBeGreaterThan(1);
        expect(seen.every((p) => p === seen[0])).toBe(true);
        seen[0]?.close?.();
        expect(calls).toEqual(['b']);
    });
});
