// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A QR code drawn with plain views: the encoder is pure JavaScript, so the
 * wallet needs no native SVG module to show one. Each run of dark modules in
 * a row is one view, which keeps even a dense code to a few hundred views.
 *
 * Always dark on white with a quiet zone, whatever the theme: scanners read
 * that reliably and inverted codes they often do not.
 *
 * The Privasys logo sits in the centre, over about 5% of the modules. The code
 * is made at the highest error-correction level (H, up to 30% recovered), so
 * the modules under the logo are read back from the rest.
 */

import { Image } from 'expo-image';
import qrcode from 'qrcode-generator';
import { useMemo } from 'react';
import { View } from 'react-native';

const LOGO = require('../../assets/icon.production.png');
/** The logo's side, as a share of the code's (the icon has its own white margin). */
const LOGO_SHARE = 0.24;

export function QrCode({ value, size = 220 }: { value: string; size?: number }) {
    const { n, runs } = useMemo(() => {
        const qr = qrcode(0, 'H');
        qr.addData(value);
        qr.make();
        const count = qr.getModuleCount();
        const out: { r: number; c: number; len: number }[] = [];
        for (let r = 0; r < count; r++) {
            for (let c = 0; c < count; c++) {
                if (!qr.isDark(r, c)) continue;
                const start = c;
                while (c + 1 < count && qr.isDark(r, c + 1)) c++;
                out.push({ r, c: start, len: c - start + 1 });
            }
        }
        return { n: count, runs: out };
    }, [value]);

    const quiet = 4;
    // At least 3 points a module, so a dense code stays readable: it may then
    // come out a little larger than asked.
    const cell = Math.max(3, Math.floor(size / (n + quiet * 2)));
    const pad = cell * quiet;
    const side = cell * n;

    return (
        <View
            accessible
            accessibilityRole="image"
            style={{ backgroundColor: '#FFFFFF', padding: pad, alignSelf: 'center', borderRadius: 8 }}
        >
            <View style={{ width: side, height: side }}>
                {runs.map(({ r, c, len }) => (
                    <View
                        key={`${r}.${c}`}
                        style={{
                            position: 'absolute',
                            left: c * cell,
                            top: r * cell,
                            width: len * cell,
                            height: cell,
                            backgroundColor: '#000000',
                        }}
                    />
                ))}
            </View>
            <Image
                source={LOGO}
                accessible={false}
                style={{
                    position: 'absolute',
                    left: pad + (side * (1 - LOGO_SHARE)) / 2,
                    top: pad + (side * (1 - LOGO_SHARE)) / 2,
                    width: side * LOGO_SHARE,
                    height: side * LOGO_SHARE,
                    borderRadius: cell * 2,
                }}
            />
        </View>
    );
}
