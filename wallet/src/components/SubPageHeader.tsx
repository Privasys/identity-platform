// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Shared header for sub-pages (Settings and Profile both push into these).
 * One consistent look: brand-green rounded bar, a circular back button, and an
 * optional right-hand action. Screens render their own header because the root
 * Stack runs with headerShown:false.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useMemo, type ReactNode } from 'react';
import { Pressable, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text, usePalette, type Palette } from '@/components/Themed';

export function SubPageHeader({ title, right }: { title: string; right?: ReactNode }) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const goBack = () => {
        if (router.canGoBack()) router.back();
        else router.replace('/(tabs)/profile');
    };
    return (
        <RNView style={[styles.header, { paddingTop: insets.top + 12 }]}>
            <Pressable onPress={goBack} style={styles.back} hitSlop={10} accessibilityLabel="Back">
                <Ionicons name="chevron-back" size={24} color="#FFFFFF" />
            </Pressable>
            <Text style={styles.title}>{title}</Text>
            <RNView style={styles.right}>{right}</RNView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    header: {
        backgroundColor: p.green,
        paddingHorizontal: 16,
        paddingBottom: 16,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottomLeftRadius: 28,
        borderBottomRightRadius: 28,
    },
    back: {
        width: 36,
        height: 36,
        borderRadius: 18,
        backgroundColor: 'rgba(255,255,255,0.2)',
        alignItems: 'center',
        justifyContent: 'center',
    },
    title: { fontSize: 17, fontWeight: '600', color: '#FFFFFF', flex: 1, textAlign: 'center' },
    right: { width: 36, alignItems: 'flex-end' },
});
