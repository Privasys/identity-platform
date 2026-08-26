import { Ionicons } from '@expo/vector-icons';
import { Tabs } from 'expo-router';
import React from 'react';
import { useTranslation } from 'react-i18next';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { usePalette } from '@/components/Themed';

/** Bar height above whatever the system draws below it. */
const TAB_BAR_CONTENT_HEIGHT = 60;

export default function TabLayout() {
    const p = usePalette();
    const { t } = useTranslation();
    const insets = useSafeAreaInsets();
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
            <Tabs.Screen
                name="index"
                options={{
                    title: t('tabs.home'),
                    tabBarIcon: ({ color, size }: { color: string; size: number }) => (
                        <Ionicons name="home" size={size} color={color} />
                    )
                }}
            />
            <Tabs.Screen
                name="profile"
                options={{
                    title: t('tabs.profile'),
                    tabBarIcon: ({ color, size }: { color: string; size: number }) => (
                        <Ionicons name="person-circle" size={size} color={color} />
                    )
                }}
            />
            <Tabs.Screen
                name="drive"
                options={{
                    title: t('tabs.drive'),
                    tabBarIcon: ({ color, size }: { color: string; size: number }) => (
                        <Ionicons name="folder" size={size} color={color} />
                    )
                }}
            />
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
