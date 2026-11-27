// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Text and View drawn in the current colour scheme's palette.
 */

import { Image as DefaultImage } from 'expo-image';
import { Text as DefaultText, View as DefaultView } from 'react-native';

import { lightPalette, darkPalette, type Palette } from '@/constants/colors';

import { useColorScheme } from './useColorScheme';

/**
 * The active semantic palette for the current colour scheme. Screens build
 * their styles from these tokens instead of hardcoded hex values:
 *
 *   const p = usePalette();
 *   const styles = useMemo(() => makeStyles(p), [p]);
 */
export function usePalette(): Palette {
    return useColorScheme() === 'dark' ? darkPalette : lightPalette;
}

export type { Palette };

export function Text(props: DefaultText['props']) {
    const { style, ...otherProps } = props;
    const color = usePalette().textPrimary;
    return <DefaultText style={[{ color }, style]} {...otherProps} />;
}

export function View(props: DefaultView['props']) {
    const { style, ...otherProps } = props;
    const backgroundColor = usePalette().screenBg;
    return <DefaultView style={[{ backgroundColor }, style]} {...otherProps} />;
}

export const Image = DefaultImage;
