// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Guards on the Intl-free date formatter.
 *
 * Hermes ships no `Intl.DateTimeFormat`, so every date the wallet renders goes
 * through `formatPattern` and the `format` block of a downloaded pack. A
 * pattern is data, not code: it arrives from a locale file, and a bug here
 * shows up as a wrong date on a consent or expiry screen rather than a crash.
 */

import { EN_GB_FORMATS, formatPattern, formatTechnical } from '@/i18n/formatters';
import type { LocaleFormats } from '@/i18n/formatters';

// 2026-03-03T09:07:05, a Tuesday. Single-digit day, month, hour and minute so
// zero-padding is actually exercised.
const SAMPLE = new Date(2026, 2, 3, 9, 7, 5);

const LV: LocaleFormats = {
    ...EN_GB_FORMATS,
    months: [
        'janvāra', 'februāra', 'marta', 'aprīļa', 'maija', 'jūnija',
        'jūlija', 'augusta', 'septembra', 'oktobra', 'novembra', 'decembra',
    ],
};

describe('formatPattern', () => {
    it('renders each token at the right width', () => {
        expect(formatPattern(SAMPLE, 'yyyy', EN_GB_FORMATS)).toBe('2026');
        expect(formatPattern(SAMPLE, 'yy', EN_GB_FORMATS)).toBe('26');
        expect(formatPattern(SAMPLE, 'MMMM', EN_GB_FORMATS)).toBe('March');
        expect(formatPattern(SAMPLE, 'MMM', EN_GB_FORMATS)).toBe('Mar');
        expect(formatPattern(SAMPLE, 'MM', EN_GB_FORMATS)).toBe('03');
        expect(formatPattern(SAMPLE, 'M', EN_GB_FORMATS)).toBe('3');
        expect(formatPattern(SAMPLE, 'dddd', EN_GB_FORMATS)).toBe('Tuesday');
        expect(formatPattern(SAMPLE, 'ddd', EN_GB_FORMATS)).toBe('Tue');
        expect(formatPattern(SAMPLE, 'dd', EN_GB_FORMATS)).toBe('03');
        expect(formatPattern(SAMPLE, 'd', EN_GB_FORMATS)).toBe('3');
        expect(formatPattern(SAMPLE, 'HH:mm', EN_GB_FORMATS)).toBe('09:07');
        expect(formatPattern(SAMPLE, 'H:mm:ss', EN_GB_FORMATS)).toBe('9:07:05');
    });

    it('renders the en-GB defaults', () => {
        expect(formatPattern(SAMPLE, EN_GB_FORMATS.date, EN_GB_FORMATS)).toBe('03/03/2026');
        expect(formatPattern(SAMPLE, EN_GB_FORMATS.dateLong, EN_GB_FORMATS)).toBe('3 March 2026');
    });

    it('passes quoted literals through untouched', () => {
        // Without quoting, every letter of "gada" is a token and the day number
        // lands inside the word. This is the whole reason quoting exists.
        expect(formatPattern(SAMPLE, "yyyy. 'gada' d. MMMM", LV)).toBe('2026. gada 3. marta');
        expect(formatPattern(SAMPLE, "yyyy 'm.' MMMM d 'd.'", LV)).toBe('2026 m. marta 3 d.');
    });

    it('unquotes a doubled quote to one apostrophe', () => {
        expect(formatPattern(SAMPLE, "''", EN_GB_FORMATS)).toBe("'");
        expect(formatPattern(SAMPLE, "d 'o''clock'", EN_GB_FORMATS)).toBe("3 o'clock");
    });

    it("renders Maltese's apostrophe-inside-a-literal long date", () => {
        // mt.json's dateLong is the hardest pattern shipped: a quoted literal
        // that itself contains an escaped apostrophe, between two tokens.
        const mt = { ...EN_GB_FORMATS, months: [...EN_GB_FORMATS.months] };
        mt.months[2] = 'Marzu';
        expect(formatPattern(SAMPLE, "d 'ta''' MMMM yyyy", mt)).toBe("3 ta' Marzu 2026");
    });

    it('leaves unknown characters alone rather than throwing', () => {
        expect(formatPattern(SAMPLE, '>>> ??? <<<', EN_GB_FORMATS)).toBe('>>> ??? <<<');
    });

    it('survives a pack whose name arrays are too short', () => {
        // A malformed downloaded pack must degrade, not crash a consent screen.
        const broken = { ...EN_GB_FORMATS, months: [], days: [] };
        expect(formatPattern(SAMPLE, 'dddd d MMMM yyyy', broken)).toBe(' 3  2026');
    });
});

describe('formatTechnical', () => {
    it('never groups digits in an identifier', () => {
        // Grouping inside a measurement would make two identical hashes read as
        // different, which is the opposite of what an attestation screen is for.
        expect(formatTechnical('1234567890')).toBe('1234567890');
        expect(formatTechnical(1234567890)).toBe('1234567890');
    });
});
