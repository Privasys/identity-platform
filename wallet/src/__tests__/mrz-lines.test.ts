// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What decides that a camera frame holds a document's machine readable zone,
 * and which part of the frame is the page.
 *
 * The specimen is the one printed in ICAO 9303, so nothing here is anyone's.
 */

import { mrzRows, pageCrop, parseMrzLines, type TextLine } from '../../modules/native-emrtd/src/mrz-lines';

const NAMES = 'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<';
const NUMBERS = 'L898902C36UTO7408122F1204159ZE184226B<<<<<10';

const line = (text: string, y: number, x = 0.2, w = 0.5): TextLine => ({ text, x, y, w, h: 0.03 });

describe('the rows of the zone', () => {
    it('are picked out of everything else on the page, top to bottom', () => {
        // A reader hands lines back in no particular order.
        const rows = mrzRows([
            line(NUMBERS, 0.74),
            line('PASSPORT PASSEPORT', 0.2),
            line(NAMES, 0.7),
            line('ERIKSSON', 0.3),
        ]);
        expect(rows.map((r) => r.text)).toEqual([NAMES, NUMBERS]);
    });

    it('are recognised with the spaces a reader puts between characters', () => {
        const spaced = NUMBERS.replace(/(.{11})/g, '$1 ');
        expect(mrzRows([line(spaced, 0.7)])).toHaveLength(1);
    });

    it('do not include a line that is merely long', () => {
        expect(mrzRows([line('This passport contains 32 pages and is valid', 0.5)])).toEqual([]);
    });

    // Some passports fill the second row to the last character.
    it('include a row with no filler in it', () => {
        expect(mrzRows([line('L898902C36UTO7408122F1204159ZE184226B1234510', 0.7)])).toHaveLength(1);
    });
});

describe('reading the zone', () => {
    it('gives the chip access fields when every check digit passes', () => {
        expect(parseMrzLines([NAMES, NUMBERS])).toMatchObject({
            documentNumber: 'L898902C3',
            dateOfBirth: '740812',
            dateOfExpiry: '120415',
            // The library withholds a state it does not know, and UTO is not one.
            issuingState: 'UTO',
        });
    });

    it('reads a one-letter state without its filler', () => {
        const german = 'P<D<<MUSTERMANN<<ERIKA<<<<<<<<<<<<<<<<<<<<<<';
        expect(parseMrzLines([german, NUMBERS])?.issuingState).toBe('D');
    });

    // A wrong key would be refused by the chip after a slow scan, so a misread
    // has to come back as nothing and never as a guess.
    it('gives nothing when a character of the document number was misread', () => {
        const misread = NUMBERS.replace('L898902C3', 'L898902C8');
        expect(parseMrzLines([NAMES, misread])).toBeNull();
    });

    it('gives nothing when a date was misread', () => {
        expect(parseMrzLines([NAMES, NUMBERS.replace('7408122', '7408132')])).toBeNull();
        expect(parseMrzLines([NAMES, NUMBERS.replace('1204159', '1204169')])).toBeNull();
    });

    it('gives nothing for one row on its own', () => {
        expect(parseMrzLines([NUMBERS])).toBeNull();
    });
});

describe('the page around the zone', () => {
    const frame = { width: 1920, height: 1080 };
    const rows = [line(NAMES, 0.7), line(NUMBERS, 0.74)];

    it('stands on the zone and is wider than it', () => {
        const crop = pageCrop(rows, frame, 1.42);
        // Wider than the rows on both sides.
        expect(crop.x).toBeLessThan(0.2);
        expect(crop.x + crop.w).toBeGreaterThan(0.7);
        // Reaches below the last row and well above the first.
        expect(crop.y + crop.h).toBeGreaterThan(0.77);
        expect(crop.y).toBeLessThan(0.3);
    });

    it('has the shape of the page, not of the frame', () => {
        const crop = pageCrop(rows, frame, 1.42);
        const shape = (crop.w * frame.width) / (crop.h * frame.height);
        expect(shape).toBeGreaterThan(1.2);
        expect(shape).toBeLessThan(1.6);
    });

    it('stays inside the frame when the page runs off its edge', () => {
        const crop = pageCrop([line(NAMES, 0.05, 0.6, 0.5), line(NUMBERS, 0.09, 0.6, 0.5)], frame, 1.42);
        expect(crop.x).toBeGreaterThanOrEqual(0);
        expect(crop.y).toBeGreaterThanOrEqual(0);
        expect(crop.x + crop.w).toBeLessThanOrEqual(1);
        expect(crop.y + crop.h).toBeLessThanOrEqual(1);
        expect(crop.w).toBeGreaterThan(0);
        expect(crop.h).toBeGreaterThan(0);
    });

    it('is the whole frame when there is nothing to stand on', () => {
        expect(pageCrop([], frame, 1.42)).toEqual({ x: 0, y: 0, w: 1, h: 1 });
    });
});
