// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Shared header for sub-pages (Settings and Profile both push into these).
 * One consistent look: brand-green rounded bar, a circular back button, and an
 * optional right-hand action. Screens render their own header because the root
 * Stack runs with headerShown:false.
 *
 * On a wide window (components/WideFrame) the band goes: a list or the item
 * open beside it is headed by its title alone, with nothing to go back to;
 * a screen of its own or a task keeps a back button, in the action blue.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useMemo, type ReactNode } from 'react';
import { Pressable, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { HeaderBleed } from '@/components/HeaderBleed';
import { usePane } from '@/components/pane';

export function SubPageHeader({ title, right }: { title: string; right?: ReactNode }) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const router = useRouter();
    const goBack = () => {
        if (router.canGoBack()) router.back();
        else router.replace('/(tabs)');
    };
    const pane = usePane();
    if (pane) {
        const back = pane.kind === 'page' || pane.kind === 'task';
        const big = pane.kind === 'list';
        return (
            <RNView style={[styles.plain, { paddingTop: insets.top + (pane.kind === 'task' ? 16 : 24) }]}>
                {back && (
                    <Pressable onPress={goBack} style={styles.plainBack} hitSlop={10} accessibilityLabel="Back">
                        <Ionicons name="chevron-back" size={24} color={p.action} />
                    </Pressable>
                )}
                <Text style={big ? styles.plainTitleBig : styles.plainTitle} accessibilityRole="header" numberOfLines={1}>
                    {title}
                </Text>
                <RNView style={styles.plainRight}>{right}</RNView>
            </RNView>
        );
    }
    return (
        <RNView style={[styles.header, { paddingTop: insets.top + 12 }]}>
            <HeaderBleed />
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
    plain: { flexDirection: 'row', alignItems: 'center', gap: 8, paddingHorizontal: 24, paddingBottom: 8 },
    plainBack: { width: 36, height: 36, marginLeft: -8, alignItems: 'center', justifyContent: 'center' },
    plainTitle: { flex: 1, fontSize: 22, fontWeight: '700', color: p.textPrimary },
    plainTitleBig: { flex: 1, fontSize: 30, fontWeight: '700', color: p.textPrimary, letterSpacing: -0.5 },
    plainRight: { minWidth: 36, alignItems: 'flex-end' },
});
