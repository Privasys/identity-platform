// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import type { TextStyle } from 'react-native';

import type { Palette } from '@/components/Themed';

/**
 * The one look for a section name on a tab: small, bold, muted capitals.
 *
 * Shared because it drifted. Profile and Access each had their own copy, near
 * enough to pass for the same, and Settings had grown a larger, darker title of
 * its own, so moving between tabs changed the page's voice for no reason. A
 * screen adds its own spacing around this and nothing else.
 */
export function sectionTitleStyle(p: Palette): TextStyle {
    return {
        fontSize: 12,
        fontWeight: '700',
        color: p.textMuted,
        letterSpacing: 0.8,
        textTransform: 'uppercase',
    };
}
