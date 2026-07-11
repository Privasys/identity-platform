/**
 * Learn more about Light and Dark modes:
 * https://docs.expo.io/guides/color-schemes/
 */

import { Image as DefaultImage } from 'expo-image';
import { Text as DefaultText, View as DefaultView, Button as DefaultButton } from 'react-native';

import Colors, { lightPalette, darkPalette, type Palette } from '@/constants/colors';

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

type ThemeProps = { lightColor?: string; darkColor?: string };

export type TextProps = ThemeProps & DefaultText['props'];
export type ViewProps = ThemeProps & DefaultView['props'];
export type ButtonProps = ThemeProps & DefaultButton['props'];

export function useThemeColor(
    props: { light?: string; dark?: string },
    colorName: keyof typeof Colors.light & keyof typeof Colors.dark
) {
    const raw = useColorScheme();
    const theme = raw === 'dark' ? 'dark' : 'light';
    const colorFromProps = props[theme];

    if (colorFromProps) {
        return colorFromProps;
    } else {
        return Colors[theme][colorName];
    }
}

export function Text(props: TextProps) {
    const { style, lightColor, darkColor, ...otherProps } = props;
    const color = useThemeColor({ light: lightColor, dark: darkColor }, 'text');

    return <DefaultText style={[{ color }, style]} {...otherProps} />;
}

export function View(props: ViewProps) {
    const { style, lightColor, darkColor, ...otherProps } = props;
    const backgroundColor = useThemeColor({ light: lightColor, dark: darkColor }, 'background');

    return <DefaultView style={[{ backgroundColor }, style]} {...otherProps} />;
}

export function Button(props: ButtonProps) {
    const { lightColor, darkColor, ...otherProps } = props;
    const backgroundColor = useThemeColor({ light: lightColor, dark: darkColor }, 'background');

    return <DefaultButton color={backgroundColor} {...otherProps} />;
}

export const Image = DefaultImage;
