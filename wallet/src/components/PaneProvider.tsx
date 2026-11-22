// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The pane a screen is drawn in (components/pane), the same value from one
 * render to the next until its kind, width or layout changes.
 *
 * A fresh value each time the wide frame draws re-renders every screen that
 * reads it; a screen that then sets its navigation options (Stack.Screen) has
 * the frame draw again, and so on without end: "Maximum update depth
 * exceeded", Service Details on iPad in 1.4.77. The close action is kept
 * current without changing the value.
 */

import { useMemo, useRef, type ReactNode } from 'react';

import { PaneContext, type Pane, type PaneKind } from '@/components/pane';

export function PaneProvider({
    kind,
    width,
    twoPane,
    close,
    children,
}: {
    kind: PaneKind;
    width: number;
    twoPane: boolean;
    close?: () => void;
    children: ReactNode;
}) {
    const closeRef = useRef(close);
    closeRef.current = close;
    const canClose = close != null;
    const value = useMemo<Pane>(
        () => ({ kind, width, twoPane, close: canClose ? () => closeRef.current?.() : undefined }),
        [kind, width, twoPane, canClose],
    );
    return <PaneContext.Provider value={value}>{children}</PaneContext.Provider>;
}
