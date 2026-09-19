import { Ionicons } from '@expo/vector-icons';
import { Tabs } from 'expo-router';
import React, { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { AppState } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { usePalette } from '@/components/Themed';
import { useCapabilityAsksStore } from '@/stores/capability-asks';
import { useVaultApprovalsStore } from '@/stores/vaultApprovals';

/** Bar height above whatever the system draws below it. */
const TAB_BAR_CONTENT_HEIGHT = 60;

export default function TabLayout() {
    const p = usePalette();
    const { t } = useTranslation();
    const insets = useSafeAreaInsets();
    const pending = useVaultApprovalsStore((s) => s.pending.length);
    const asks = useCapabilityAsksStore((s) => s.asks.length);
    const waiting = pending + asks;
    // Look for open access requests whenever the wallet comes to the front,
    // not only when Access is open: the badge is how the holder learns of one
    // whose push they swiped away, from whichever tab they are on.
    useEffect(() => {
        void useCapabilityAsksStore.getState().refresh();
        const sub = AppState.addEventListener('change', (state) => {
            if (state === 'active') void useCapabilityAsksStore.getState().refresh();
        });
        return () => sub.remove();
    }, []);
    return (
        <Tabs
            screenOptions={{
                headerShown: false,
                tabBarActiveTintColor: p.blue,
                tabBarInactiveTintColor: p.textMuted,
                // Height is measured, not assumed. A hard-coded 88 happened to
                // clear an iPhone home indicator and nothing else: Android runs
                // edge-to-edge from Expo SDK 54, so the gesture pill or the
                // three-button bar is drawn OVER the app and ate the bottom of
                // the tab bar on devices whose inset is larger (2026-08-26).
                tabBarStyle: {
                    backgroundColor: p.card,
                    borderTopColor: p.border,
                    borderTopWidth: 0.5,
                    paddingTop: 4,
                    paddingBottom: insets.bottom,
                    height: TAB_BAR_CONTENT_HEIGHT + insets.bottom
                },
                tabBarLabelStyle: {
                    fontSize: 11,
                    fontWeight: '600'
                }
            }}
        >
            {/* Profile leads and is the landing tab: it is `index`, which is
                what the launch URL and every router.replace('/(tabs)') resolve
                to. An initialRouteName would reorder the bar but not change
                where the app opens. */}
            <Tabs.Screen
                name="index"
                options={{
                    title: t('tabs.profile'),
                    tabBarIcon: ({ color, size }: { color: string; size: number }) => (
                        <Ionicons name="person-circle" size={size} color={color} />
                    )
                }}
            />
            {/* The badge carries anything waiting on a decision, so a pending
                approval is visible from whichever tab the holder is on. */}
            <Tabs.Screen
                name="access"
                options={{
                    title: t('tabs.access'),
                    tabBarBadge: waiting > 0 ? waiting : undefined,
                    tabBarBadgeStyle: { backgroundColor: p.danger },
                    tabBarIcon: ({ color, size }: { color: string; size: number }) => (
                        <Ionicons name="key" size={size} color={color} />
                    )
                }}
            />
            {/* Drive is not a tab: it is the holder's own data, so it opens
                from Profile, under Personal Data. */}
            <Tabs.Screen
                name="settings"
                options={{
                    title: t('tabs.settings'),
                    tabBarIcon: ({ color, size }: { color: string; size: number }) => (
                        <Ionicons name="settings" size={size} color={color} />
                    )
                }}
            />
        </Tabs>
    );
}
