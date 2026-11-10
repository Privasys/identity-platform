// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Finding the machine readable zone in text read off a document, and working
 * out where the page around it is.
 *
 * Kept free of native modules so it can be tested on its own: it is the part
 * that decides when a camera frame is good enough to stop on.
 */

import { parse as parseMrz } from 'mrz';

import type { MrzScan } from './NativeEmrtd.types';

/** One line of text read from a frame. Positions are fractions of the frame,
 *  measured from its top left, with the frame upright. */
export interface TextLine {
    text: string;
    x: number;
    y: number;
    w: number;
    h: number;
}

/** A part of a frame, in the same fractions. */
export interface FrameCrop {
    x: number;
    y: number;
    w: number;
    h: number;
}

const compact = (text: string) => text.toUpperCase().replace(/\s/g, '');

/** What a row of the zone looks like: its own alphabet, at its own length. */
const ROW = /^[A-Z0-9<]{28,44}$/;

/**
 * The lines that look like rows of the zone, top to bottom.
 *
 * A reader hands lines back in no particular order, and the rows only parse in
 * the order they are printed.
 */
export function mrzRows(lines: TextLine[]): TextLine[] {
    return lines
        .filter((l) => looksLikeRow(compact(l.text)))
        .sort((a, b) => a.y - b.y);
}

/**
 * A long line of ordinary print fits the alphabet too once its spaces are
 * gone. A row of the zone also carries filler, or the run of digits that makes
 * up its numbers and dates.
 */
function looksLikeRow(text: string): boolean {
    if (!ROW.test(text)) return false;
    return text.includes('<') || text.replace(/[^0-9]/g, '').length >= 10;
}

/**
 * Pick the MRZ lines out of the OCR'd text and parse them with the `mrz`
 * library, which validates each field's ICAO check digit. We only accept a
 * result whose document-number / DOB / expiry check digits pass, so an OCR
 * misread can never produce a wrong BAC key (it just isn't returned, and the
 * caller scans the next frame).
 *
 * The library reports a field and its check digit separately, and a field
 * reads as valid whenever its characters are of the right kind. Until
 * 2026-11 only the fields were looked at here, so a misread document number
 * was accepted as checked. It is the check digits that are looked at now.
 */
export function parseMrzLines(rawLines: string[]): MrzScan | null {
    const candidates = rawLines.map(compact).filter((l) => ROW.test(l));

    // TD3 = 2 lines (~44 chars), TD1 = 3 lines (~30 chars).
    for (const n of [2, 3]) {
        if (candidates.length < n) continue;
        try {
            const res = parseMrz(candidates.slice(-n));
            const f = res.fields;
            // Require the check digit to PASS (true). A null/unknown result means
            // the library could not verify it (often a garbled check-digit char),
            // which previously slipped through and yielded a wrong BAC key.
            const detailValid = (field: string) => {
                const d = (res.details as Array<{ field: string; valid: boolean | null }>).find((x) => x.field === field);
                return d?.valid === true;
            };
            if (
                f.documentNumber && f.birthDate && f.expirationDate &&
                detailValid('documentNumber') && detailValid('birthDate') && detailValid('expirationDate') &&
                detailValid('documentNumberCheckDigit') && detailValid('birthDateCheckDigit') &&
                detailValid('expirationDateCheckDigit')
            ) {
                return {
                    documentNumber: f.documentNumber,
                    dateOfBirth: f.birthDate,
                    dateOfExpiry: f.expirationDate,
                    // The exact accepted MRZ lines, joined — for the enclave's
                    // visual↔chip cross-reference (GPG45 box 3).
                    mrz: candidates.slice(-n).join(''),
                };
            }
        } catch {
            // not these lines / not an MRZ — try the next grouping
        }
    }
    return null;
}

/** How much of the page's width the zone's rows span, on both sizes of
 *  document: 44 characters across a 125 mm passport page, 30 across an
 *  85.6 mm card. */
const ROW_SHARE_OF_PAGE = 0.89;

/**
 * The part of the frame that holds the document page, worked out from where
 * the zone was read: the zone runs along the bottom of the page and spans a
 * known share of its width, so the page is the rectangle standing on it.
 *
 * This is what lets the holder put the document anywhere in view. A margin is
 * left all round, because a page cut too tight is worse for the verifier than
 * one with some table showing.
 *
 * @param rows   the zone's rows, from `mrzRows`
 * @param frame  the frame's size in pixels, upright
 * @param ratio  the page's width over its height
 */
export function pageCrop(
    rows: TextLine[],
    frame: { width: number; height: number },
    ratio: number,
): FrameCrop {
    const whole = { x: 0, y: 0, w: 1, h: 1 };
    if (rows.length === 0 || !(frame.width > 0) || !(frame.height > 0) || !(ratio > 0)) return whole;
    // The bottom two rows: they are as wide as each other on every document,
    // and a stray line above them would otherwise pull the page out of shape.
    rows = rows.slice(-2);

    // Work in pixels: the page's shape only means something there.
    const left = Math.min(...rows.map((r) => r.x)) * frame.width;
    const right = Math.max(...rows.map((r) => r.x + r.w)) * frame.width;
    const bottom = Math.max(...rows.map((r) => r.y + r.h)) * frame.height;
    const rowsWidth = right - left;
    if (!(rowsWidth > 0)) return whole;

    const pageW = rowsWidth / ROW_SHARE_OF_PAGE;
    const pageH = pageW / ratio;
    const margin = pageW * 0.1;
    const centre = (left + right) / 2;
    // The rows sit a few millimetres above the page's bottom edge.
    const pageBottom = bottom + pageW * 0.04;

    const x0 = Math.max(0, centre - pageW / 2 - margin);
    const x1 = Math.min(frame.width, centre + pageW / 2 + margin);
    const y0 = Math.max(0, pageBottom - pageH - margin);
    const y1 = Math.min(frame.height, pageBottom + margin);
    if (!(x1 > x0) || !(y1 > y0)) return whole;

    return {
        x: x0 / frame.width,
        y: y0 / frame.height,
        w: (x1 - x0) / frame.width,
        h: (y1 - y0) / frame.height,
    };
}
