// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The three drawings of the ID check: where the chip symbol is, what to
 * photograph, and how to lay the phone on the document.
 *
 * Drawn with plain views and the built-in Animated API, so they add no native
 * library and no asset to the bundle. Each drawing is driven by one looping
 * 0..1 value; with Reduce Motion on it rests on a single representative frame.
 * Colours are fixed: a passport cover is navy on either theme.
 */

import { useEffect, useRef, type ReactNode } from 'react';
import { AccessibilityInfo, Animated, Easing, Platform, StyleSheet, Text, View } from 'react-native';

export type IdDoc = 'passport' | 'id-card';

const NAVY = '#1E3A6E';
const GOLD = '#F2C94C';
const PAPER = '#EEF2E6';
const PAPER_BACK = '#DDE5D6';
const INK = '#2A3238';
const STEEL = '#94A3B8';
const LIGHT = '#F1F5F9';
const DARK = '#0B1220';
const GREEN = '#34E89E';
const BLUE = '#00BCF2';
const GREY = '#C9D3D8';
const RULE = '#B9C6CC';
const MONO = Platform.select({ ios: 'Menlo', android: 'monospace' });

/** One looping 0..1 driver; rests at `rest` when the holder prefers no motion. */
function useLoop(duration: number, rest: number): Animated.Value {
    const v = useRef(new Animated.Value(rest)).current;
    useEffect(() => {
        let live = true;
        let loop: Animated.CompositeAnimation | undefined;
        AccessibilityInfo.isReduceMotionEnabled()
            .then((reduce) => {
                if (!live || reduce) return;
                v.setValue(0);
                loop = Animated.loop(
                    Animated.timing(v, { toValue: 1, duration, easing: Easing.linear, useNativeDriver: true }),
                );
                loop.start();
            })
            .catch(() => undefined);
        return () => {
            live = false;
            loop?.stop();
        };
    }, [v, duration]);
    return v;
}

/** The ICAO chip symbol: two bars with a circle between them. */
function ChipMark({ left, top, width, bar, color, ground }: {
    left: number; top: number; width: number; bar: number; color: string; ground: string;
}) {
    const gap = Math.round(bar * 0.7);
    const d = bar * 2 + gap - 2;
    return (
        <View style={{ position: 'absolute', left, top, width, height: bar * 2 + gap }}>
            <View style={{ height: bar, backgroundColor: color }} />
            <View style={{ height: bar, backgroundColor: color, marginTop: gap }} />
            <View
                style={{
                    position: 'absolute', left: (width - d) / 2, top: 1, width: d, height: d, borderRadius: d / 2,
                    backgroundColor: color, borderWidth: Math.max(2, Math.round(bar * 0.4)), borderColor: ground,
                    alignItems: 'center', justifyContent: 'center',
                }}
            >
                <View style={{ width: d / 4, height: d / 4, borderRadius: d / 8, backgroundColor: ground }} />
            </View>
        </View>
    );
}

/** A passport cover with its emblem. */
function Cover({ left, top, width, height }: { left: number; top: number; width: number; height: number }) {
    const e = Math.round(width * 0.46);
    return (
        <View style={{ position: 'absolute', left, top, width, height, borderRadius: 7, backgroundColor: NAVY }}>
            <View
                style={{
                    position: 'absolute', left: (width - e) / 2, top: Math.round(height * 0.2), width: e, height: e,
                    borderRadius: e / 2, borderWidth: 3, borderColor: GOLD, alignItems: 'center', justifyContent: 'center',
                }}
            >
                <View style={{ position: 'absolute', width: e - 6, height: 2, backgroundColor: GOLD }} />
                <View style={{ position: 'absolute', width: 2, height: e - 6, backgroundColor: GOLD }} />
            </View>
        </View>
    );
}

/** An ID card, front side. */
function Card({ left, top, width, height }: { left: number; top: number; width: number; height: number }) {
    return (
        <View style={{ position: 'absolute', left, top, width, height, borderRadius: 8, backgroundColor: PAPER, borderWidth: 1, borderColor: GREY }}>
            <View style={{ position: 'absolute', left: 8, top: 10, width: width * 0.26, height: height * 0.6, borderRadius: 3, backgroundColor: GREY }} />
            <View style={{ position: 'absolute', left: width * 0.42, top: height * 0.44, width: width * 0.44, height: 4, borderRadius: 2, backgroundColor: RULE }} />
            <View style={{ position: 'absolute', left: width * 0.42, top: height * 0.62, width: width * 0.34, height: 4, borderRadius: 2, backgroundColor: RULE }} />
        </View>
    );
}

function Frame({ label, height, children }: { label: string; height: number; children: ReactNode }) {
    return (
        <View style={[styles.frame, { height }]} accessible accessibilityRole="image" accessibilityLabel={label}>
            {children}
        </View>
    );
}

/** Where the chip symbol is: the document, with the symbol enlarged beside it. */
export function ChipSymbolArt({ doc, label }: { doc: IdDoc; label: string }) {
    const t = useLoop(2400, 0.5);
    const scale = t.interpolate({ inputRange: [0, 0.5, 1], outputRange: [1, 1.08, 1] });
    const glow = t.interpolate({ inputRange: [0, 0.5, 1], outputRange: [0.35, 1, 0.35] });
    const passport = doc === 'passport';
    return (
        <Frame label={label} height={200}>
            {passport ? <Cover left={150} top={18} width={92} height={140} /> : <Card left={136} top={52} width={112} height={72} />}
            <Animated.View style={[StyleSheet.absoluteFill, { opacity: glow }]}>
                {passport
                    ? <ChipMark left={184} top={124} width={24} bar={5} color={GOLD} ground={NAVY} />
                    : <ChipMark left={214} top={60} width={22} bar={5} color={INK} ground={PAPER} />}
            </Animated.View>
            <View style={[styles.pointer, passport ? { left: 108, top: 122, width: 78, transform: [{ rotate: '8deg' }] } : { left: 115, top: 83, width: 112, transform: [{ rotate: '-17deg' }] }]} />
            <Animated.View style={[styles.lens, { transform: [{ scale }] }]}>
                <ChipMark left={14} top={30} width={64} bar={12} color={DARK} ground={LIGHT} />
            </Animated.View>
        </Frame>
    );
}

/** What to photograph: a phone over the document, reading its lines of code. */
export function PhotoPageArt({ doc, label }: { doc: IdDoc; label: string }) {
    const t = useLoop(3600, 0.6);
    const drop = t.interpolate({ inputRange: [0, 0.12, 0.35, 1], outputRange: [-46, -46, 0, 0] });
    const phone = t.interpolate({ inputRange: [0, 0.12, 0.35, 0.8, 1], outputRange: [0, 0, 1, 1, 0] });
    const read = t.interpolate({ inputRange: [0, 0.38, 0.5, 0.78, 1], outputRange: [0, 0, 0.9, 0.9, 0] });
    const passport = doc === 'passport';
    const lines = passport
        ? ['P<UTOERIKSSON<<ANNA<MARIA<<<<<', 'L898902C36UTO7408122F3204153<<']
        : ['I<UTOD231458907<<<<<<<<<<<<<<<', '7408122F3204153UTO<<<<<<<<<<<6', 'ERIKSSON<<ANNA<MARIA<<<<<<<<<<'];
    const top = passport ? 98 : 84;
    const band = passport ? 28 : 38;
    return (
        <Frame label={label} height={200}>
            {passport && <View style={[styles.sheet, { top: 20, height: 76, backgroundColor: PAPER_BACK }]} />}
            <View style={[styles.sheet, { top, height: 190 - top, backgroundColor: PAPER }]}>
                {passport && (
                    <>
                        <View style={{ position: 'absolute', left: 12, top: 12, width: 34, height: 42, borderRadius: 3, backgroundColor: GREY }} />
                        <View style={[styles.rule, { left: 56, top: 14, width: 96 }]} />
                        <View style={[styles.rule, { left: 56, top: 26, width: 76 }]} />
                        <View style={[styles.rule, { left: 56, top: 38, width: 88 }]} />
                    </>
                )}
                <View style={{ position: 'absolute', left: 10, right: 10, bottom: 7 }}>
                    {lines.map((l) => (
                        <Text key={l} allowFontScaling={false} numberOfLines={1} style={styles.code}>{l}</Text>
                    ))}
                </View>
                <Animated.View style={[styles.band, { height: band, opacity: read }]} />
            </View>
            <Animated.View style={[styles.phoneLandscape, { opacity: phone, transform: [{ translateY: drop }] }]}>
                <View style={styles.phoneButton} />
            </Animated.View>
        </Frame>
    );
}

/**
 * How to scan: the phone slides onto the document while the chip is read.
 *
 * `open` draws a passport open at its photo page, for a chip that is inside
 * that page; otherwise it is closed. `reader` is where this phone's reader is,
 * which decides how far onto the document the phone comes to rest: its top
 * edge on the document, or its middle.
 */
export function ChipScanArt({ doc, label, open = false, reader = 'top' }: {
    doc: IdDoc; label: string; open?: boolean; reader?: 'top' | 'middle';
}) {
    const t = useLoop(4000, 0.7);
    const passport = doc === 'passport';
    // The middle of the document, and where the phone's top edge rests so its
    // reader sits there.
    const centre = !passport ? 96 : open ? 107 : 89;
    const rest = reader === 'top' ? centre - 14 : centre - 62;
    const slide = t.interpolate({ inputRange: [0, 0.08, 0.38, 0.9, 1], outputRange: [60, 60, 0, 0, 60] });
    const wave = (d: number) => ({
        opacity: t.interpolate({ inputRange: [0, 0.4 + d, 0.55 + d, 0.85 + d, 1], outputRange: [0, 0, 0.9, 0, 0] }),
        transform: [{ scale: t.interpolate({ inputRange: [0, 0.4 + d, 0.85 + d, 1], outputRange: [0.6, 0.6, 1.5, 1.5] }) }],
    });
    const dot = (i: number) =>
        t.interpolate({ inputRange: [0, 0.42 + i * 0.06, 0.5 + i * 0.06, 0.92, 1], outputRange: [0.25, 0.25, 1, 1, 0.25] });
    return (
        <Frame label={label} height={220}>
            {!passport ? (
                <Card left={62} top={52} width={136} height={88} />
            ) : open ? (
                <>
                    <View style={[styles.sheet, { top: 2, height: 58, backgroundColor: PAPER_BACK }]} />
                    <View style={[styles.sheet, { top: 62, height: 90, backgroundColor: PAPER }]}>
                        <View style={{ position: 'absolute', left: 12, top: 12, width: 34, height: 42, borderRadius: 3, backgroundColor: GREY }} />
                        <View style={[styles.rule, { left: 56, top: 14, width: 96 }]} />
                        <View style={[styles.rule, { left: 56, top: 26, width: 76 }]} />
                        <View style={[styles.rule, { left: 12, top: 66, width: 154 }]} />
                        <View style={[styles.rule, { left: 12, top: 76, width: 154 }]} />
                    </View>
                </>
            ) : (
                <Cover left={74} top={14} width={112} height={150} />
            )}
            {[0, 0.05, 0.1].map((d, i) => (
                <Animated.View key={d} style={[styles.wave, { left: 114 - i * 10, top: centre - 16 - i * 10, width: 32 + i * 20, height: 32 + i * 20, borderRadius: 16 + i * 10 }, wave(d)]} />
            ))}
            <Animated.View style={[styles.phonePortrait, { top: rest, transform: [{ translateY: slide }] }]}>
                <View style={styles.phoneSpeaker} />
                <View style={[styles.phoneReader, reader === 'middle' && { marginTop: 34 }]} />
                <View style={styles.dots}>
                    {[0, 1, 2, 3, 4].map((i) => (
                        <Animated.View key={i} style={[styles.dot, { opacity: dot(i) }]} />
                    ))}
                </View>
            </Animated.View>
        </Frame>
    );
}

const styles = StyleSheet.create({
    // Cut to its own box, so a part that slides in never lands on the text
    // under the drawing.
    frame: { width: 260, alignSelf: 'center', overflow: 'hidden' },
    pointer: { position: 'absolute', height: 3, borderRadius: 2, backgroundColor: STEEL },
    lens: {
        position: 'absolute', left: 20, top: 54, width: 100, height: 100, borderRadius: 50,
        backgroundColor: LIGHT, borderWidth: 4, borderColor: STEEL,
    },
    sheet: { position: 'absolute', left: 40, width: 180, borderRadius: 6, borderWidth: 1, borderColor: GREY },
    rule: { position: 'absolute', height: 5, borderRadius: 3, backgroundColor: RULE },
    code: { fontFamily: MONO, fontSize: 7.5, lineHeight: 11, color: INK },
    band: { position: 'absolute', left: 5, right: 5, bottom: 4, borderRadius: 5, borderWidth: 3, borderColor: GREEN },
    phoneLandscape: {
        position: 'absolute', left: 22, top: 84, width: 216, height: 110, borderRadius: 14,
        borderWidth: 6, borderColor: STEEL, justifyContent: 'center',
    },
    phoneButton: { position: 'absolute', left: -12, width: 6, height: 26, borderRadius: 3, backgroundColor: STEEL },
    wave: { position: 'absolute', borderWidth: 3, borderColor: GREEN },
    phonePortrait: {
        position: 'absolute', left: 84, top: 92, width: 92, height: 124, borderRadius: 12,
        backgroundColor: LIGHT, borderWidth: 5, borderColor: STEEL, alignItems: 'center',
    },
    phoneSpeaker: { marginTop: 4, width: 24, height: 5, borderRadius: 3, backgroundColor: STEEL },
    phoneReader: { marginTop: 4, width: 52, height: 26, borderRadius: 6, borderWidth: 3, borderColor: BLUE },
    dots: { flexDirection: 'row', gap: 4, marginTop: 10 },
    dot: { width: 9, height: 9, borderRadius: 5, backgroundColor: BLUE },
});
