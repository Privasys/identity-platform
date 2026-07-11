import { Ionicons } from '@expo/vector-icons';
import { Tabs } from 'expo-router';
import React from 'react';

import { usePalette } from '@/components/Themed';
import { useSettingsStore } from '@/stores/settings';

export default function TabLayout() {
    const p = usePalette();
    const driveEnabled = useSettingsStore((s) => s.driveEnabled);
    return (
        <Tabs
            screenOptions={{
                headerShown: false,
                tabBarActiveTintColor: p.blue,
                tabBarInactiveTintColor: p.textMuted,
                tabBarStyle: {
                    backgroundColor: p.card,
                    borderTopColor: p.border,
                    borderTopWidth: 0.5,
                    paddingTop: 4,
                    height: 88
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
                    title: 'Home',
                    tabBarIcon: ({ color, size }: { color: string; size: number }) => (
                        <Ionicons name="home" size={size} color={color} />
                    )
                }}
            />
            <Tabs.Screen
                name="profile"
                options={{
                    title: 'Profile',
                    tabBarIcon: ({ color, size }: { color: string; size: number }) => (
                        <Ionicons name="person-circle" size={size} color={color} />
                    )
                }}
            />
            <Tabs.Screen
                name="drive"
                options={{
                    title: 'Drive',
                    // href:null hides the tab (and its route) until enabled in
                    // Settings — the Drive integration is in progress.
                    href: driveEnabled ? undefined : null,
                    tabBarIcon: ({ color, size }: { color: string; size: number }) => (
                        <Ionicons name="folder" size={size} color={color} />
                    )
                }}
            />
            <Tabs.Screen
                name="settings"
                options={{
                    title: 'Settings',
                    tabBarIcon: ({ color, size }: { color: string; size: number }) => (
                        <Ionicons name="settings" size={size} color={color} />
                    )
                }}
            />
        </Tabs>
    );
}
