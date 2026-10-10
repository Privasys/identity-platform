// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A QR code drawn with plain views: the encoder is pure JavaScript, so the
 * wallet needs no native SVG module to show one. Each row is one view of
 * cells, which keeps a version-4 code (33 modules) to a few hundred views.
 *
 * Always dark on white with a quiet zone, whatever the theme: scanners read
 * that reliably and inverted codes they often do not.
 */

import qrcode from 'qrcode-generator';
import { useMemo } from 'react';
import { View } from 'react-native';

export function QrCode({ value, size = 220 }: { value: string; size?: number }) {
    const matrix = useMemo(() => {
        const qr = qrcode(0, 'M');
        qr.addData(value);
        qr.make();
        const n = qr.getModuleCount();
        return Array.from({ length: n }, (_, r) => Array.from({ length: n }, (_, c) => qr.isDark(r, c)));
    }, [value]);

    const quiet = 4;
    const cell = Math.floor(size / (matrix.length + quiet * 2));
    const pad = cell * quiet;

    return (
        <View
            accessible
            accessibilityRole="image"
            style={{ backgroundColor: '#FFFFFF', padding: pad, alignSelf: 'center', borderRadius: 8 }}
        >
            {matrix.map((row, r) => (
                <View key={r} style={{ flexDirection: 'row' }}>
                    {row.map((dark, c) => (
                        <View
                            key={c}
                            style={{ width: cell, height: cell, backgroundColor: dark ? '#000000' : '#FFFFFF' }}
                        />
                    ))}
                </View>
            ))}
        </View>
    );
}
