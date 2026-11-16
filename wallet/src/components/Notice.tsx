// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The message strip (stores/notice): drops in under the status bar, stays
 * about three seconds, and goes. A tap dismisses it. When it appears, the
 * phone gives the short success vibration.
 */

import { Ionicons } from '@expo/vector-icons';
import * as Haptics from 'expo-haptics';
import { useEffect, useMemo, useRef } from 'react';
import { AccessibilityInfo, Animated, Pressable, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { useNoticeStore } from '@/stores/notice';

const SHOWN_MS = 3200;

export function Notice() {
    const notice = useNoticeStore((s) => s.notice);
    const clear = useNoticeStore((s) => s.clear);
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const insets = useSafeAreaInsets();
    const shown = useRef(new Animated.Value(0)).current;

    useEffect(() => {
        if (!notice) return;
        void Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => undefined);
        AccessibilityInfo.announceForAccessibility(notice.body ? `${notice.title}. ${notice.body}` : notice.title);
        shown.setValue(0);
        Animated.timing(shown, { toValue: 1, duration: 220, useNativeDriver: true }).start();
        const timer = setTimeout(() => {
            Animated.timing(shown, { toValue: 0, duration: 200, useNativeDriver: true }).start(() => clear(notice.id));
        }, SHOWN_MS);
        return () => clearTimeout(timer);
    }, [notice, shown, clear]);

    if (!notice) return null;
    return (
        <Animated.View
            pointerEvents="box-none"
            style={[
                styles.wrap,
                { top: insets.top + 8 },
                { opacity: shown, transform: [{ translateY: shown.interpolate({ inputRange: [0, 1], outputRange: [-16, 0] }) }] },
            ]}
        >
            <Pressable style={styles.strip} onPress={() => clear(notice.id)} accessibilityRole="alert">
                <RNView style={styles.icon}>
                    <Ionicons name="checkmark" size={15} color={p.onGreen} />
                </RNView>
                <RNView style={styles.words}>
                    <Text style={styles.title} numberOfLines={2}>
                        {notice.title}
                    </Text>
                    {notice.body ? (
                        <Text style={styles.body} numberOfLines={3}>
                            {notice.body}
                        </Text>
                    ) : null}
                </RNView>
            </Pressable>
        </Animated.View>
    );
}

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        wrap: { position: 'absolute', left: 12, right: 12, zIndex: 1000, elevation: 20 },
        strip: {
            flexDirection: 'row',
            alignItems: 'center',
            gap: 12,
            backgroundColor: p.card,
            borderRadius: 14,
            borderWidth: 1,
            borderColor: p.border,
            paddingVertical: 12,
            paddingHorizontal: 14,
            shadowColor: '#0F172A',
            shadowOpacity: 0.18,
            shadowRadius: 18,
            shadowOffset: { width: 0, height: 8 },
        },
        icon: { width: 26, height: 26, borderRadius: 13, backgroundColor: p.green, alignItems: 'center', justifyContent: 'center' },
        words: { flex: 1, gap: 1 },
        title: { fontSize: 15, fontWeight: '600', color: p.textPrimary },
        body: { fontSize: 13, lineHeight: 18, color: p.textSecondary },
    });
