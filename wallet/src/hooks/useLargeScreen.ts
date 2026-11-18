// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { useWindowDimensions } from 'react-native';

/**
 * The space the wallet is given, read live: it changes when a foldable opens
 * or closes, when an iPad window is resized, or when the phone turns. Layout
 * follows the space, never the device type or the orientation.
 */

/** Below this shorter side the wallet is a phone layout (portrait, full width). */
export const LARGE_SCREEN_MIN_SIDE = 600;

/** The widest a column of content is drawn; wider space centres it. */
export const READABLE_WIDTH = 720;

/** Whether the window is large enough to turn and to centre content
 *  (tablets, unfolded phones). */
export function useLargeScreen(): boolean {
    const { width, height } = useWindowDimensions();
    return Math.min(width, height) >= LARGE_SCREEN_MIN_SIDE;
}

/** The side padding that centres a READABLE_WIDTH column in a window this wide. */
export function columnGutter(width: number): number {
    return Math.max(0, Math.floor((width - READABLE_WIDTH) / 2));
}

/** From this width the wallet draws a sidebar in place of the tab bar
 *  (tablets in either orientation, unfolded phones). Narrower windows, an
 *  iPad in Split View for one, keep the phone layout. */
export const WIDE_MIN_WIDTH = 840;

/** From this width a section shows its list and the open item side by side. */
export const TWO_PANE_MIN_WIDTH = 1100;

/** Whether the window is wide enough for the sidebar. */
export function useWideLayout(): boolean {
    return useWindowDimensions().width >= WIDE_MIN_WIDTH;
}
