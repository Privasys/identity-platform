// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Draws a Markdown document (services/markdown) with native text: no web
 * view, nothing loaded. A link is offered only for web and mail addresses,
 * and opens in the phone's browser after the holder sees where it goes.
 */

import { useMemo, useState, type ReactNode } from 'react';
import { Alert, Linking, ScrollView, StyleSheet, View as RNView } from 'react-native';
import { useTranslation } from 'react-i18next';

import { Text, usePalette, type Palette } from '@/components/Themed';
import { columnWidths, fitColumns, openableLink, parseMarkdown, type Block, type Inline } from '@/services/markdown';

import { MONO } from '@/constants/fonts';

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
                return <MarkdownTable key={k} table={b} id={k} inline={inline} styles={styles} />;
        }
    };

    return <RNView style={styles.doc}>{blocks.map((b, i) => block(b, String(i)))}</RNView>;
}

/**
 * A table whose columns line up in every row. Each cell is a box of a set
 * width holding its text: a text cell sized by flex grows to its own content
 * on iOS, so each row placed its columns differently. The widths fill the
 * room the table has when it fits, and the table scrolls sideways when not.
 */
function MarkdownTable({
    table,
    id,
    inline,
    styles,
}: {
    table: Extract<Block, { t: 'table' }>;
    id: string;
    inline: (nodes: Inline[], key?: string) => ReactNode[];
    styles: Styles;
}) {
    const [room, setRoom] = useState(0);
    const natural = useMemo(() => columnWidths(table.head, table.rows), [table]);
    const widths = fitColumns(natural, room);
    return (
        <ScrollView
            horizontal
            style={styles.tableBox}
            onLayout={(e) => setRoom(Math.floor(e.nativeEvent.layout.width) - 2)}
        >
            <RNView>
                {[table.head, ...table.rows].map((row, r) => (
                    <RNView key={r} style={[styles.tr, r === 0 && styles.th]}>
                        {widths.map((w, c) => (
                            <RNView key={c} style={[styles.td, { width: w }]}>
                                <Text
                                    style={[styles.tdText, r === 0 && styles.strong, { textAlign: table.align[c] ?? 'left' }]}
                                >
                                    {row[c] ? inline(row[c], `${id}.${r}.${c}`) : null}
                                </Text>
                            </RNView>
                        ))}
                    </RNView>
                ))}
            </RNView>
        </ScrollView>
    );
}

type Styles = ReturnType<typeof makeStyles>;

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
        // Widths come from columnWidths and fitColumns: the same in every row.
        td: { paddingHorizontal: 10, paddingVertical: 8 },
        tdText: { fontSize: 14, lineHeight: 20, color: p.textPrimary },
    });

