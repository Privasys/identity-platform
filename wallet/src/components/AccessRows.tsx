// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The rows the Access tab and its lists share: one provider, one app.
 */

import { Ionicons } from '@expo/vector-icons';
import { Pressable, View as RNView, type StyleProp, type TextStyle, type ViewStyle } from 'react-native';
import { useTranslation } from 'react-i18next';

import { Text, type Palette } from '@/components/Themed';
import {
    liveIn,
    productNames,
    recordsIn,
    whatOf,
    type AppNode,
    type ProviderNode,
} from '@/utils/access-tree';

/** The styles a screen lends these rows, so they sit in its own card. */
export interface AccessRowStyles {
    row: StyleProp<ViewStyle>;
    rowInfo: StyleProp<ViewStyle>;
    rowTitle: StyleProp<TextStyle>;
    rowEnded: StyleProp<TextStyle>;
    rowMeta: StyleProp<TextStyle>;
    rowEndedNote: StyleProp<TextStyle>;
}

/**
 * One provider: its name, then the account when there is one, or every
 * account, and the products connected. A provider with nothing live left
 * says so rather than vanishing.
 */
export function ProviderRow({
    provider,
    nowSeconds,
    onPress,
    styles,
    p,
}: {
    provider: ProviderNode;
    nowSeconds: number;
    onPress: () => void;
    styles: AccessRowStyles;
    p: Palette;
}) {
    const { t } = useTranslation();
    const records = recordsIn(provider);
    const ended = records.length > 0 && liveIn(records, nowSeconds) === 0 && !provider.signIn;
    const accounts = provider.accounts.map((a) => a.account).join(', ');
    const products = productNames(provider);
    if (provider.signIn) products.push(t('access.signInTitle'));
    return (
        <Pressable style={styles.row} onPress={onPress}>
            <RNView style={styles.rowInfo}>
                <Text style={[styles.rowTitle, ended && styles.rowEnded]}>{provider.name}</Text>
                {!!accounts && <Text style={styles.rowMeta}>{accounts}</Text>}
                <Text style={styles.rowMeta}>{products.join(', ')}</Text>
                {ended && <Text style={styles.rowEndedNote}>{t('access.stateEnded')}</Text>}
            </RNView>
            <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
        </Pressable>
    );
}

/** One app, and what it can use, named the way each service declared it. */
export function AppRow({
    app,
    nowSeconds,
    onPress,
    styles,
    p,
}: {
    app: AppNode;
    nowSeconds: number;
    onPress: () => void;
    styles: AccessRowStyles;
    p: Palette;
}) {
    const { t } = useTranslation();
    const records = app.rows.map((r) => r.record);
    const live = records.filter((r) => liveIn([r], nowSeconds) === 1);
    const what: string[] = [];
    for (const r of live.length > 0 ? live : records) {
        const w = whatOf(r);
        if (!what.includes(w)) what.push(w);
    }
    return (
        <Pressable style={styles.row} onPress={onPress}>
            <RNView style={styles.rowInfo}>
                <Text style={[styles.rowTitle, live.length === 0 && styles.rowEnded]}>
                    {app.appName || t('capability.unnamedApp')}
                </Text>
                <Text style={styles.rowMeta}>{what.join(', ')}</Text>
                {live.length === 0 && <Text style={styles.rowEndedNote}>{t('access.stateEnded')}</Text>}
            </RNView>
            <Ionicons name="chevron-forward" size={18} color={p.textMuted} />
        </Pressable>
    );
}
