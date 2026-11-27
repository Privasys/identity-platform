// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * QR codes drawn as SVG, with the Privasys mark in the centre.
 */

import { logoMark } from './icons';
import qrcode from 'qrcode-generator';

/** The logo's side as a share of a QR code's, quiet zone excluded. */
export const QR_LOGO_SHARE = 0.24;

/**
 * The Privasys mark on a white rounded tile, as SVG to lay over the centre
 * of a QR code. The tile gives the mark a clear edge against the modules;
 * its gradient ids differ from ICON_LOGO's, which shares pages with it.
 */
export function qrLogoSvg(x: number, y: number, side: number): string {
    const inset = side * 0.14;
    const mark = side - inset * 2;
    return `<g shape-rendering="geometricPrecision">`
        + `<rect x="${x}" y="${y}" width="${side}" height="${side}" rx="${side * 0.18}" fill="#fff"/>`
        + `<svg x="${x + inset}" y="${y + inset}" width="${mark}" height="${mark}" viewBox="0 0 500 500">`
        + logoMark('qrp', 'fill="#fff"') + '</svg></g>';
}

/**
 * A QR code with the Privasys logo in its centre. The code is made at the
 * highest error-correction level (H, up to 30% recovered), so the modules
 * under the logo are read back from the rest.
 */
export function renderQRSvg(payload: string): string {
    try {
        const qr = qrcode(0, 'H');
        qr.addData(payload);
        qr.make();
        const count = qr.getModuleCount();
        const cellSize = Math.max(3, Math.floor(200 / count));
        const margin = 4;
        const side = count * cellSize;
        const logo = side * QR_LOGO_SHARE;
        const at = margin + (side - logo) / 2;
        const svg = qr.createSvgTag({ cellSize, margin, scalable: true });
        const end = svg.lastIndexOf('</svg>');
        if (end < 0) return svg;
        return svg.slice(0, end) + qrLogoSvg(at, at, logo) + svg.slice(end);
    } catch {
        return `<div style="padding:16px;font-size:11px;word-break:break-all">${payload}</div>`;
    }
}
