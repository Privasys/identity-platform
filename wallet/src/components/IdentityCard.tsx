// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The holder's own card at the top of Profile: their picture, name and email,
 * and whether their ID has been checked. It carries the logo's two halves in a
 * corner, the same halves that open when the wallet unlocks
 * (components/AppLock).
 *
 * It is the Profile tab's header: there is no band above it.
 */

import Ionicons from '@expo/vector-icons/Ionicons';
import { useMemo } from 'react';
import { Image, Pressable, StyleSheet, View as RNView } from 'react-native';
import { useTranslation } from 'react-i18next';

import { Text, usePalette, type Palette } from '@/components/Themed';

export function IdentityCard({
    name,
    email,
    avatar,
    idChecked,
    onChooseAvatar,
}: {
    name: string;
    email?: string;
    avatar: string;
    idChecked: boolean;
    onChooseAvatar: () => void;
}) {
    const { t } = useTranslation();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    return (
        <RNView style={styles.card} testID="identity-card">
            <RNView style={[styles.half, styles.green]} pointerEvents="none" />
            <RNView style={[styles.half, styles.blue]} pointerEvents="none" />
            {/* A picture only when there is one: the avatar the holder set, or
                failing that the photo from their ID. Tapping it sets the
                avatar; with no picture, a line of text does. */}
            {avatar ? (
                <Pressable
                    onPress={onChooseAvatar}
                    style={styles.avatarWrap}
                    accessibilityRole="button"
                    accessibilityLabel={t('profile.photoTitle')}
                >
                    <Image
                        source={{ uri: avatar }}
                        style={styles.avatar}
                        onError={(e) => console.warn('[avatar] failed to load', e.nativeEvent?.error)}
                    />
                </Pressable>
            ) : null}
            <Text style={styles.name} accessibilityRole="header">
                {name}
            </Text>
            {email ? <Text style={styles.email}>{email}</Text> : null}
            {avatar ? null : (
                <Pressable onPress={onChooseAvatar} hitSlop={8} style={styles.addPhoto}>
                    <Text style={styles.addPhotoText}>{t('profile.addPhoto')}</Text>
                </Pressable>
            )}
            {idChecked ? (
                <RNView style={styles.chip}>
                    <Ionicons name="shield-checkmark" size={13} color={p.onGreen} />
                    <Text style={styles.chipText}>{t('profile.cardIdChecked')}</Text>
                </RNView>
            ) : null}
        </RNView>
    );
}

/** The corner halves: squares turned 45°, as on the splash. */
const HALF = 150;

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        card: {
            backgroundColor: p.idCard,
            borderRadius: 20,
            padding: 20,
            paddingTop: 24,
            marginBottom: 24,
            overflow: 'hidden',
            minHeight: 150,
            justifyContent: 'flex-end',
        },
        half: { position: 'absolute', width: HALF, height: HALF, transform: [{ rotate: '-45deg' }] },
        green: { backgroundColor: p.green, right: -22, top: -98 },
        blue: { backgroundColor: p.blue, right: -98, top: -22 },
        avatarWrap: { marginBottom: 14, alignSelf: 'flex-start' },
        avatar: { width: 64, height: 64, borderRadius: 32, borderWidth: 2, borderColor: p.onIdCard },
        name: { fontSize: 22, fontWeight: '700', color: p.onIdCard, letterSpacing: -0.3, marginRight: 80 },
        email: { fontSize: 14, color: p.onIdCardMuted, marginTop: 2 },
        addPhoto: { marginTop: 10, alignSelf: 'flex-start' },
        addPhotoText: { fontSize: 15, fontWeight: '600', color: p.blue },
        chip: {
            flexDirection: 'row',
            alignItems: 'center',
            gap: 5,
            alignSelf: 'flex-start',
            marginTop: 12,
            paddingHorizontal: 10,
            paddingVertical: 4,
            borderRadius: 999,
            backgroundColor: p.green,
        },
        chipText: { fontSize: 12, fontWeight: '600', color: p.onGreen },
    });
