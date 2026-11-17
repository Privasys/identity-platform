// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Draws a Markdown document (services/markdown) with native text: no web
 * view, nothing loaded. A link is offered only for web and mail addresses,
 * and opens in the phone's browser after the holder sees where it goes.
 */

import { useMemo } from 'react';
import { Alert, Linking, Platform, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useTranslation } from 'react-i18next';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { openableLink, parseMarkdown, type Block, type Inline } from '@/services/markdown';

const MONO = Platform.select({ ios: 'Menlo', android: 'monospace' });

export function MarkdownView({ source }: { source: string }) {
    const p = usePalette();
    const styles = useMemo(() => makeStyles(p), [p]);
    const { t } = useTranslation();
    const blocks = useMemo(() => parseMarkdown(source), [source]);

    const openLink = (href: string) => {
        if (!openableLink(href)) return;
        Alert.alert(t('drive.linkTitle'), href, [
            { text: t('common.cancel'), style: 'cancel' },
            { text: t('drive.linkOpen'), onPress: () => void Linking.openURL(href) },
        ]);
    };

    const inline = (nodes: Inline[], key = ''): React.ReactNode[] =>
        nodes.map((n, i) => {
            const k = `${key}${i}`;
            switch (n.t) {
                case 'text':
                    return n.v;
                case 'strong':
                    return <Text key={k} style={styles.strong}>{inline(n.c, k)}</Text>;
                case 'em':
                    return <Text key={k} style={styles.em}>{inline(n.c, k)}</Text>;
                case 'del':
                    return <Text key={k} style={styles.del}>{inline(n.c, k)}</Text>;
                case 'code':
                    return <Text key={k} style={styles.inlineCode}>{n.v}</Text>;
                case 'link':
                    return openableLink(n.href) ? (
                        <Text key={k} style={styles.link} onPress={() => openLink(n.href)} accessibilityRole="link">
                            {inline(n.c, k)}
                        </Text>
                    ) : (
                        <Text key={k}>{inline(n.c, k)}</Text>
                    );
            }
        });

    const block = (b: Block, k: string): React.ReactNode => {
        switch (b.t) {
            case 'heading':
                return (
                    <Text key={k} style={[styles.heading, styles[`h${Math.min(b.level, 4)}` as 'h1']]} accessibilityRole="header">
                        {inline(b.c, k)}
                    </Text>
                );
            case 'para':
                return <Text key={k} style={styles.para} selectable>{inline(b.c, k)}</Text>;
            case 'code':
                return (
                    <ScrollView key={k} horizontal style={styles.codeBox} contentContainerStyle={styles.codeInner}>
                        <Text style={styles.code} selectable>{b.v}</Text>
                    </ScrollView>
                );
            case 'quote':
                return <RNView key={k} style={styles.quote}>{b.c.map((c, i) => block(c, `${k}.${i}`))}</RNView>;
            case 'rule':
                return <RNView key={k} style={styles.rule} />;
            case 'list':
                return (
                    <RNView key={k} style={styles.list}>
                        {b.items.map((it, i) => (
                            <RNView key={i} style={styles.item}>
                                <Text style={styles.bullet}>
                                    {it.checked !== undefined ? (it.checked ? '☑' : '☐') : b.ordered ? `${b.start + i}.` : '•'}
                                </Text>
                                <RNView style={styles.itemBody}>{it.c.map((c, j) => block(c, `${k}.${i}.${j}`))}</RNView>
                            </RNView>
                        ))}
                    </RNView>
                );
            case 'table':
                return (
                    <ScrollView key={k} horizontal style={styles.tableBox}>
                        <RNView>
                            {[b.head, ...b.rows].map((row, r) => (
                                <RNView key={r} style={[styles.tr, r === 0 && styles.th]}>
                                    {row.map((cell, c) => (
                                        <Text
                                            key={c}
                                            style={[
                                                styles.td,
                                                r === 0 && styles.strong,
                                                { textAlign: b.align[c] ?? 'left' },
                                            ]}
                                        >
                                            {inline(cell, `${k}.${r}.${c}`)}
                                        </Text>
                                    ))}
                                </RNView>
                            ))}
                        </RNView>
                    </ScrollView>
                );
        }
    };

    return <RNView style={styles.doc}>{blocks.map((b, i) => block(b, String(i)))}</RNView>;
}

const makeStyles = (p: Palette) =>
    StyleSheet.create({
        doc: { gap: 12 },
        heading: { fontWeight: '700', color: p.textPrimary, marginTop: 6 },
        h1: { fontSize: 24, lineHeight: 30 },
        h2: { fontSize: 20, lineHeight: 26 },
        h3: { fontSize: 17, lineHeight: 23 },
        h4: { fontSize: 15, lineHeight: 21 },
        para: { fontSize: 15, lineHeight: 23, color: p.textPrimary },
        strong: { fontWeight: '700' },
        em: { fontStyle: 'italic' },
        del: { textDecorationLine: 'line-through' },
        inlineCode: { fontFamily: MONO, fontSize: 13.5, backgroundColor: p.cardAlt },
        link: { color: p.action, textDecorationLine: 'underline' },
        codeBox: { backgroundColor: p.cardAlt, borderRadius: 10 },
        codeInner: { padding: 12 },
        code: { fontFamily: MONO, fontSize: 13, lineHeight: 19, color: p.textPrimary },
        quote: { borderLeftWidth: 3, borderLeftColor: p.border, paddingLeft: 12, gap: 8 },
        rule: { height: StyleSheet.hairlineWidth, backgroundColor: p.border, marginVertical: 4 },
        list: { gap: 6 },
        item: { flexDirection: 'row', gap: 8 },
        bullet: { fontSize: 15, lineHeight: 23, color: p.textSecondary, minWidth: 18 },
        itemBody: { flex: 1, gap: 6 },
        tableBox: { borderWidth: StyleSheet.hairlineWidth, borderColor: p.border, borderRadius: 8 },
        tr: { flexDirection: 'row', borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: p.border },
        th: { backgroundColor: p.cardAlt },
        td: { minWidth: 90, maxWidth: 240, paddingHorizontal: 10, paddingVertical: 8, fontSize: 14, color: p.textPrimary },
    });
