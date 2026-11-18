// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * On a large screen the wallet draws its content in a centred column
 * (hooks/useLargeScreen), but the green header band should still run edge to
 * edge, as it does on a phone: it carries the status bar, whose white text
 * would otherwise sit on the light background beside the column. Placed as a
 * header's first child, this paints the header's colour out to both screen
 * edges. As the first child it is drawn beneath the header's title and
 * buttons, with no zIndex: a negative one can put it behind an ancestor's
 * background. On a phone it draws nothing.
 */

import { StyleSheet, useWindowDimensions, View } from 'react-native';

import { usePalette } from '@/components/Themed';
import { columnGutter, useLargeScreen } from '@/hooks/useLargeScreen';

export function HeaderBleed({ colour, radius = 28 }: { colour?: string; radius?: number }) {
    const large = useLargeScreen();
    const { width } = useWindowDimensions();
    const p = usePalette();
    const gutter = columnGutter(width);
    if (!large || gutter === 0) return null;
    return (
        <View
            pointerEvents="none"
            style={[
                StyleSheet.absoluteFill,
                {
                    left: -gutter,
                    right: -gutter,
                    backgroundColor: colour ?? p.green,
                    borderBottomLeftRadius: radius,
                    borderBottomRightRadius: radius,
                },
            ]}
        />
    );
}
