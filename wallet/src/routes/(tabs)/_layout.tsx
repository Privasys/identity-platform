import { Ionicons } from '@expo/vector-icons';
import { Tabs } from 'expo-router';
import React from 'react';

export default function TabLayout() {
    return (
        <Tabs
            screenOptions={{
                headerShown: false,
                tabBarActiveTintColor: '#00BCF2',
                tabBarInactiveTintColor: '#94A3B8',
                tabBarStyle: {
                    backgroundColor: '#FFFFFF',
                    borderTopColor: '#E2E8F0',
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
                name="scan"
                options={{
                    title: 'Scan',
                    tabBarIcon: ({ color, size }: { color: string; size: number }) => (
                        <Ionicons name="qr-code-outline" size={size} color={color} />
                    )
                }}
            />
            <Tabs.Screen
                name="about"
                options={{
                    title: 'About',
                    tabBarIcon: ({ color, size }: { color: string; size: number }) => (
                        <Ionicons name="information-circle" size={size} color={color} />
                    )
                }}
            />
        </Tabs>
    );
}
