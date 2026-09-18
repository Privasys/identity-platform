// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The identifiers behind the wallet: the Privasys account, the canonical DID
 * that is the same on every device, and this device's own DID.
 *
 * Moved off the Profile tab, where three long monospace strings sat above the
 * holder's own data and pushed it down the screen. They are for support and
 * for the curious, both of whom can take one tap.
 */

import { Ionicons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import { useMemo } from 'react';
import { Alert, Pressable, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { useTranslation } from 'react-i18next';

import { SubPageHeader } from '@/components/SubPageHeader';
import { Text, usePalette, type Palette } from '@/components/Themed';
import { useProfileStore } from '@/stores/profile';

export default function IdentitiesScreen() {
    const profile = useProfileStore((s) => s.profile);
    const insets = useSafeAreaInsets();
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { t } = useTranslation();

    const copy = (label: string, value?: string) => {
        if (!value) return;
        void Clipboard.setStringAsync(value);
        Alert.alert(t('common.copied'), t('profile.copiedToClipboard', { label }));
    };

    // The Privasys Account id is the IdP user id of the canonical account:
    // base64url of the 32-hex-char userId carried in the canonical DID
    // (did:web:privasys.id:users:<userId>). Same derivation as
    // ensurePrivasysSession, so what is shown here matches what the IdP,
    // recovery settings and support tooling call the account.
    const canonicalUserId = profile?.canonicalDid?.split(':').pop() ?? '';
    const privasysAccountId = canonicalUserId
        ? btoa(canonicalUserId).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
        : '';

    const rows: {
        icon: keyof typeof Ionicons.glyphMap;
        tint: string;
        label: string;
        value: string;
    }[] = [
        {
            icon: 'person-circle-outline',
            tint: p.blue,
            label: t('profile.privasysAccount'),
            value: privasysAccountId,
        },
        {
            icon: 'finger-print',
            tint: p.blue,
            label: t('profile.canonicalDid'),
            value: profile?.canonicalDid || profile?.did || '',
        },
        {
            icon: 'phone-portrait-outline',
            tint: p.textSecondary,
            label: t('profile.deviceDid'),
            value: profile?.did || '',
        },
    ];

    return (
        <RNView style={styles.screen}>
            <SubPageHeader title={t('profile.identities')} />
            <ScrollView
                contentContainerStyle={[styles.content, { paddingBottom: insets.bottom + 32 }]}
                showsVerticalScrollIndicator={false}
            >
                {rows.map((row) => (
                    <Pressable
                        key={row.label}
                        style={styles.card}
                        onPress={() => copy(row.label, row.value)}
                        disabled={!row.value}
                        accessibilityRole="button"
                        accessibilityHint={t('profile.copiedToClipboard', { label: row.label })}
                    >
                        <Ionicons name={row.icon} size={20} color={row.tint} />
                        <RNView style={styles.cardText}>
                            <Text style={styles.label}>{row.label}</Text>
                            <Text style={styles.value} numberOfLines={1}>
                                {row.value || t('profile.notGenerated')}
                            </Text>
                        </RNView>
                        {!!row.value && <Ionicons name="copy-outline" size={18} color={p.textMuted} />}
                    </Pressable>
                ))}
                <Text style={styles.note}>{t('profile.privacyNote')}</Text>
            </ScrollView>
        </RNView>
    );
}

const makeStyles = (p: Palette) => StyleSheet.create({
    screen: { flex: 1, backgroundColor: p.screenBg },
    content: { padding: 20 },
    card: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
        backgroundColor: p.card,
        borderRadius: 12,
        padding: 14,
        marginBottom: 8,
    },
    cardText: { flex: 1 },
    label: {
        fontSize: 11,
        fontWeight: '600',
        color: p.textMuted,
        textTransform: 'uppercase',
        letterSpacing: 0.5,
        marginBottom: 2,
    },
    value: { fontSize: 12, fontFamily: 'Inter', color: p.textSecondary, lineHeight: 18 },
    note: { fontSize: 12, color: p.successText, marginTop: 4, lineHeight: 16 },
});
