// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The header of a tab (Profile, Access, Settings): the tab's name on the green
 * band. On a wide window the band goes and the name heads its column
 * (components/WideFrame), as an iPad or a foldable app draws it.
 */

import { useMemo } from 'react';
import { StyleSheet, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { useBandless } from '@/components/pane';
import { Text, usePalette, type Palette } from '@/components/Themed';

export function TabHeader({ title }: { title: string }) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    if (useBandless()) {
        return (
            <View style={[styles.plain, { paddingTop: insets.top + 24 }]}>
                <Text style={styles.plainTitle} accessibilityRole="header">
                    {title}
                </Text>
            </View>
        );
    }
    return (
        <View style={[styles.header, { paddingTop: insets.top + 16 }]}>
            <Text style={styles.headerTitle} accessibilityRole="header">
                {title}
            </Text>
        </View>
    );
}

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        header: {
            backgroundColor: p.green,
            paddingHorizontal: 24,
            paddingBottom: 24,
            borderBottomLeftRadius: 28,
            borderBottomRightRadius: 28,
        },
        headerTitle: { fontSize: 28, fontWeight: '700', color: '#FFFFFF', letterSpacing: -0.5 },
        plain: { paddingHorizontal: 24, paddingBottom: 8 },
        plainTitle: { fontSize: 30, fontWeight: '700', color: p.textPrimary, letterSpacing: -0.5 },
    });
