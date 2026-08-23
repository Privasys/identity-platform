// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The plural shim is a correctness contract, not a convenience.
 *
 * i18next resolves every plural key through `Intl.PluralRules`, and Hermes
 * does not implement it, so on device the wallet runs our hand-rolled CLDR
 * rules (services/../i18n/plural-rules.ts). Node in jest DOES have full ICU,
 * which makes this suite possible: it diffs the shim against the real thing
 * for every locale we ship, over every count a wallet screen could plausibly
 * show.
 *
 * A regression here is invisible in English (one/other is trivially right)
 * and wrong in 19 other languages, so it would ship unnoticed without this.
 */

import {
    selectPlural,
    pluralCategories,
    baseLanguage,
    installPluralRulesShim,
    type PluralCategory,
} from '@/i18n/plural-rules';

/** Every locale the wallet ships: 24 EU official languages plus Welsh. */
const LOCALES = [
    'en', 'fr', 'de', 'es', 'it', 'nl', 'pl', 'pt', 'sv', 'da', 'fi', 'cs',
    'el', 'hu', 'ro', 'bg', 'sk', 'sl', 'hr', 'et', 'lv', 'lt', 'ga', 'mt', 'cy',
];

/** Counts a wallet screen could realistically render. */
const MAX_N = 2000;

/**
 * Extra probes past MAX_N that hit rule boundaries: the Romance `many`
 * category fires only on exact non-zero multiples of a million.
 */
const PROBES = [999_999, 1_000_000, 1_000_001, 1_999_999, 2_000_000, 12_000_000];

/**
 * Languages whose ICU category list includes one we can never return,
 * because CLDR defines it only over fractions and we floor to integers.
 * Pinned so the omission stays deliberate rather than becoming a silent gap.
 */
const FRACTION_ONLY_MANY = ['cs', 'sk', 'lt'];

describe('plural rules shim vs ICU', () => {
    it('covers all 25 shipped locales', () => {
        expect(LOCALES).toHaveLength(25);
    });

    describe.each(LOCALES)('%s', (locale) => {
        const icu = new Intl.PluralRules(locale);

        it(`selects the same category as ICU for every integer n = 0..${MAX_N}`, () => {
            const mismatches: string[] = [];
            for (let n = 0; n <= MAX_N; n++) {
                const want = icu.select(n);
                const got = selectPlural(locale, n);
                if (want !== got) mismatches.push(`n=${n}: ICU=${want} shim=${got}`);
            }
            // Report the first few rather than 2000 lines of noise.
            expect(mismatches.slice(0, 8)).toEqual([]);
        });

        it('selects the same category as ICU at the large-number boundaries', () => {
            for (const n of PROBES) {
                expect(`${n}:${selectPlural(locale, n)}`).toBe(`${n}:${icu.select(n)}`);
            }
        });

        it('declares every category reachable with an integer', () => {
            // Under-declaring is the dangerous direction: a category we can
            // return but do not declare is a plural form no translator is
            // ever asked for, and i18next would fall back to `_other`.
            const declared = pluralCategories(locale);
            const undeclared = new Set<PluralCategory>();
            for (let n = 0; n <= MAX_N; n++) {
                const c = icu.select(n) as PluralCategory;
                if (!declared.includes(c)) undeclared.add(c);
            }
            for (const n of PROBES) {
                const c = icu.select(n) as PluralCategory;
                if (!declared.includes(c)) undeclared.add(c);
            }
            expect([...undeclared]).toEqual([]);
        });

        it('never declares a category ICU does not have', () => {
            const icuCats = new Set(icu.resolvedOptions().pluralCategories);
            for (const c of pluralCategories(locale)) expect(icuCats.has(c)).toBe(true);
        });

        it('omits an ICU category only where CLDR makes it fractions-only', () => {
            const icuCats = [...icu.resolvedOptions().pluralCategories].sort();
            const ours = [...pluralCategories(locale)].sort();
            const missing = icuCats.filter((c) => !ours.includes(c));

            expect(missing).toEqual(FRACTION_ONLY_MANY.includes(locale) ? ['many'] : []);
        });
    });
});

describe('plural rules shim behaviour', () => {
    it('reduces a region tag to its base language', () => {
        expect(baseLanguage('pt-BR')).toBe('pt');
        expect(baseLanguage('de_AT')).toBe('de');
        expect(baseLanguage('EN-gb')).toBe('en');
    });

    it('falls back to one/other for an unknown language', () => {
        expect(selectPlural('xx', 1)).toBe('one');
        expect(selectPlural('xx', 5)).toBe('other');
        expect(pluralCategories('xx')).toEqual(['one', 'other']);
    });

    it('treats a region tag as its base language', () => {
        // pt-BR must get Portuguese's "zero is singular" rule, not English's.
        expect(selectPlural('pt-BR', 0)).toBe('one');
        expect(selectPlural('pt-PT', 0)).toBe('one');
        expect(selectPlural('en-GB', 0)).toBe('other');
    });

    it('floors and absolutises, since counts are non-negative integers', () => {
        expect(selectPlural('en', 1.7)).toBe('one');
        expect(selectPlural('cy', -3)).toBe('few');
        expect(selectPlural('en', Number.NaN)).toBe('other');
    });

    it('gives Welsh all six categories at the right counts', () => {
        const cy = (n: number) => selectPlural('cy', n);
        expect(cy(0)).toBe('zero');
        expect(cy(1)).toBe('one');
        expect(cy(2)).toBe('two');
        expect(cy(3)).toBe('few');
        expect(cy(6)).toBe('many');
        expect(cy(4)).toBe('other');
    });
});

describe('installPluralRulesShim', () => {
    const native = Intl.PluralRules;
    afterEach(() => {
        (Intl as { PluralRules?: unknown }).PluralRules = native;
    });

    it('leaves a real implementation alone', () => {
        installPluralRulesShim();
        expect(Intl.PluralRules).toBe(native);
    });

    it('installs a working PluralRules when the engine has none', () => {
        // Simulate Hermes, which ships Intl but not Intl.PluralRules.
        delete (Intl as { PluralRules?: unknown }).PluralRules;
        installPluralRulesShim();

        expect(typeof Intl.PluralRules).toBe('function');
        const pr = new Intl.PluralRules('cy');
        expect(pr.select(6)).toBe('many' as PluralCategory);
        expect(pr.resolvedOptions().pluralCategories).toContain('zero');
        expect(new Intl.PluralRules('pl').select(22)).toBe('few');
    });

    it('degrades ordinals to other rather than guessing', () => {
        delete (Intl as { PluralRules?: unknown }).PluralRules;
        installPluralRulesShim();
        expect(new Intl.PluralRules('en', { type: 'ordinal' }).select(1)).toBe('other');
    });
});
