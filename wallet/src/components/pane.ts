// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Where a screen is drawn on a wide window (components/WideFrame). On a phone,
 * and in any window narrower than WIDE_MIN_WIDTH, there is no pane and screens
 * draw as they always have: the green header, a back button, the tab bar.
 *
 *   list    a section's list, beside the sidebar (Access, Drive, Settings)
 *   detail  the item opened from that list, beside it
 *   page    a screen of its own beside the sidebar (Profile and what it opens)
 *   task    a task in a centred sheet (sign-in, approvals, the ID check...)
 */

import { createContext, useContext } from 'react';

import { usePalette } from '@/components/Themed';
import { useLargeScreen } from '@/hooks/useLargeScreen';

export type PaneKind = 'list' | 'detail' | 'page' | 'task';

export interface Pane {
    kind: PaneKind;
    /** The pane's width, for screens that lay out by the room they have. */
    width: number;
    /** Whether a list has its detail beside it (a wide enough window). */
    twoPane: boolean;
    /** For the item open beside its list: closes it, so the list has the
     *  window again. */
    close?: () => void;
}

export const PaneContext = createContext<Pane | null>(null);

/** The pane this screen is drawn in, or null for the phone layout. */
export function usePane(): Pane | null {
    return useContext(PaneContext);
}

/**
 * Whether headers go without the green band: on every large screen (a tablet,
 * an unfolded phone), set up or not, and in any pane. The band is the phone's.
 */
export function useBandless(): boolean {
    const pane = usePane();
    const large = useLargeScreen();
    return !!pane || large;
}

/** The colour for icons in a header: white on the green band, the text colour
 *  where the header goes without it. */
export function useHeaderTint(): string {
    const p = usePalette();
    return useBandless() ? p.action : '#FFFFFF';
}
