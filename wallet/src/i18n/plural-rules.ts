// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A minimal `Intl.PluralRules` for the 25 locales the wallet ships.
 *
 * WHY THIS EXISTS: i18next resolves plural forms through
 * `Intl.PluralRules` (see node_modules/i18next .. `new Intl.PluralRules`).
 * Hermes implements a subset of ECMA-402 — Collator, DateTimeFormat and
 * NumberFormat delegate to the platform, but PluralRules is absent. Without
 * a shim every plural key silently falls back to `_other`, which is wrong
 * in 19 of our 25 languages and badly wrong in Welsh (six categories) and
 * Irish (five).
 *
 * We hand-roll rather than pull in @formatjs/intl-pluralrules because that
 * package needs per-locale data bundles, and the whole point of the pack
 * design is to keep the binary small. The CLDR rules for 25 fixed locales
 * fit in a few hundred bytes of arithmetic.
 *
 * SCOPE: cardinal rules over NON-NEGATIVE INTEGERS. Every plural in the
 * wallet counts discrete things (files, devices, attributes, sessions,
 * minutes), so the fractional branches of the CLDR rules (the `v`, `f` and
 * `t` operands) are unreachable and `select()` floors its input. That makes
 * `many` unreachable in Czech, Slovak and Lithuanian, where CLDR defines it
 * only for fractions, so those three declare one category fewer than ICU
 * does. Every category reachable with an integer IS implemented, including
 * the 10^6 `many` of French, Spanish, Italian and Portuguese.
 *
 * Verified category-for-category against a full ICU `Intl.PluralRules` for
 * all 25 locales — see __tests__/i18n-plurals.test.ts, which also pins the
 * three deliberate omissions above. That test is the contract; edit these
 * rules only with it passing.
 */

export type PluralCategory = 'zero' | 'one' | 'two' | 'few' | 'many' | 'other';

/** `n % m` for non-negative integers. */
const mod = (n: number, m: number) => n % m;
/** Whether `n` falls in the inclusive range [lo, hi]. */
const between = (n: number, lo: number, hi: number) => n >= lo && n <= hi;

type Rule = (n: number) => PluralCategory;

/** one when n is exactly 1. Germanic/Hellenic/Finno-Ugric default. */
const oneOther: Rule = (n) => (n === 1 ? 'one' : 'other');

/**
 * The Romance `many`: a non-zero exact multiple of a million. CLDR gives
 * French, Spanish, Italian and Portuguese this category so that "2 millions
 * de fichiers" can take a different form from "2 fichiers".
 */
const romanceMany = (n: number) => n !== 0 && mod(n, 1000000) === 0;

/**
 * CLDR cardinal rules, keyed by base language. Order of tests inside each
 * rule mirrors CLDR's own precedence (zero, one, two, few, many, other).
 */
const RULES: Record<string, Rule> = {
    // one: n = 1
    en: oneOther,
    de: oneOther,
    nl: oneOther,
    sv: oneOther,
    da: oneOther,
    fi: oneOther,
    et: oneOther,
    el: oneOther,
    hu: oneOther,
    bg: oneOther,

    // one: n = 1; many: non-zero multiple of 10^6
    it: (n) => (n === 1 ? 'one' : romanceMany(n) ? 'many' : 'other'),
    es: (n) => (n === 1 ? 'one' : romanceMany(n) ? 'many' : 'other'),

    // one: i = 0..1 (zero is singular here, unlike English);
    // many: non-zero multiple of 10^6
    pt: (n) => (n === 0 || n === 1 ? 'one' : romanceMany(n) ? 'many' : 'other'),
    fr: (n) => (n === 0 || n === 1 ? 'one' : romanceMany(n) ? 'many' : 'other'),

    // one: i = 1; few: i = 2..4   (the `many` branch is fractions-only)
    cs: (n) => (n === 1 ? 'one' : between(n, 2, 4) ? 'few' : 'other'),
    sk: (n) => (n === 1 ? 'one' : between(n, 2, 4) ? 'few' : 'other'),

    // one: i = 1;
    // few: i % 10 = 2..4 and i % 100 != 12..14;
    // many: everything else that is not 1
    pl: (n) => {
        if (n === 1) return 'one';
        const d = mod(n, 10);
        const h = mod(n, 100);
        if (between(d, 2, 4) && !between(h, 12, 14)) return 'few';
        return 'many';
    },

    // one: i % 10 = 1 and i % 100 != 11;
    // few: i % 10 = 2..4 and i % 100 != 12..14
    hr: (n) => {
        const d = mod(n, 10);
        const h = mod(n, 100);
        if (d === 1 && h !== 11) return 'one';
        if (between(d, 2, 4) && !between(h, 12, 14)) return 'few';
        return 'other';
    },

    // one: i % 100 = 1; two: i % 100 = 2; few: i % 100 = 3..4
    sl: (n) => {
        const h = mod(n, 100);
        if (h === 1) return 'one';
        if (h === 2) return 'two';
        if (between(h, 3, 4)) return 'few';
        return 'other';
    },

    // one: n % 10 = 1 and n % 100 != 11..19;
    // few: n % 10 = 2..9 and n % 100 != 11..19
    lt: (n) => {
        const d = mod(n, 10);
        const h = mod(n, 100);
        if (d === 1 && !between(h, 11, 19)) return 'one';
        if (between(d, 2, 9) && !between(h, 11, 19)) return 'few';
        return 'other';
    },

    // zero: n % 10 = 0 or n % 100 = 11..19;
    // one:  n % 10 = 1 and n % 100 != 11
    lv: (n) => {
        const d = mod(n, 10);
        const h = mod(n, 100);
        if (d === 0 || between(h, 11, 19)) return 'zero';
        if (d === 1 && h !== 11) return 'one';
        return 'other';
    },

    // one: i = 1; few: n = 0 or n % 100 = 1..19
    ro: (n) => {
        if (n === 1) return 'one';
        if (n === 0 || between(mod(n, 100), 1, 19)) return 'few';
        return 'other';
    },

    // one: n = 1; two: n = 2; few: n = 0 or n % 100 = 3..10;
    // many: n % 100 = 11..19
    mt: (n) => {
        if (n === 1) return 'one';
        if (n === 2) return 'two';
        const h = mod(n, 100);
        if (n === 0 || between(h, 3, 10)) return 'few';
        if (between(h, 11, 19)) return 'many';
        return 'other';
    },

    // one: n = 1; two: n = 2; few: n = 3..6; many: n = 7..10
    ga: (n) => {
        if (n === 1) return 'one';
        if (n === 2) return 'two';
        if (between(n, 3, 6)) return 'few';
        if (between(n, 7, 10)) return 'many';
        return 'other';
    },

    // zero: n = 0; one: n = 1; two: n = 2; few: n = 3; many: n = 6
    // The only six-category language we ship.
    cy: (n) => {
        if (n === 0) return 'zero';
        if (n === 1) return 'one';
        if (n === 2) return 'two';
        if (n === 3) return 'few';
        if (n === 6) return 'many';
        return 'other';
    },
};

/**
 * Categories each rule can actually return, for resolvedOptions().
 *
 * These are the categories a translator must supply keys for. Czech, Slovak
 * and Lithuanian are deliberately one short of ICU's list: their `many` is
 * fractions-only and so unreachable here (see the header).
 *
 * Polish is the opposite case. An integer is always one/few/many there, so
 * `other` is unreachable, but it stays declared because i18next treats
 * `_other` as its fallback form and a key set without it is fragile.
 */
const CATEGORIES: Record<string, PluralCategory[]> = {
    fr: ['one', 'many', 'other'],
    es: ['one', 'many', 'other'],
    it: ['one', 'many', 'other'],
    pt: ['one', 'many', 'other'],
    pl: ['one', 'few', 'many', 'other'],
    cs: ['one', 'few', 'other'],
    sk: ['one', 'few', 'other'],
    hr: ['one', 'few', 'other'],
    sl: ['one', 'two', 'few', 'other'],
    lt: ['one', 'few', 'other'],
    lv: ['zero', 'one', 'other'],
    ro: ['one', 'few', 'other'],
    mt: ['one', 'two', 'few', 'many', 'other'],
    ga: ['one', 'two', 'few', 'many', 'other'],
    cy: ['zero', 'one', 'two', 'few', 'many', 'other'],
};

/** The base language subtag, lowercased: 'pt-BR' -> 'pt'. */
export function baseLanguage(locale: string): string {
    return String(locale || 'en').split(/[-_]/)[0].toLowerCase();
}

/**
 * Select the CLDR plural category for `n` in `locale`. Unknown locales fall
 * back to the English one/other rule, which is what i18next would have done
 * with no PluralRules at all, only without silently collapsing to 'other'.
 */
export function selectPlural(locale: string, n: number): PluralCategory {
    const rule = RULES[baseLanguage(locale)] ?? oneOther;
    return rule(Math.floor(Math.abs(Number(n) || 0)));
}

/** Categories `locale` can produce, in CLDR order. */
export function pluralCategories(locale: string): PluralCategory[] {
    return CATEGORIES[baseLanguage(locale)] ?? ['one', 'other'];
}

/**
 * Install the shim as `Intl.PluralRules` when the engine has none.
 *
 * Idempotent, and a no-op on any engine that already implements it (Node in
 * jest, and Hermes should it ever gain support), so behaviour under test
 * matches behaviour on device wherever ICU is genuinely present.
 */
export function installPluralRulesShim(): void {
    const g = globalThis as { Intl?: Record<string, unknown> };
    if (!g.Intl) return;
    if (typeof g.Intl.PluralRules === 'function') return;

    class PluralRulesShim {
        private readonly locale: string;
        private readonly type: 'cardinal' | 'ordinal';

        constructor(locales?: string | string[], options?: { type?: 'cardinal' | 'ordinal' }) {
            this.locale = Array.isArray(locales) ? (locales[0] ?? 'en') : (locales ?? 'en');
            this.type = options?.type ?? 'cardinal';
        }

        select(n: number): PluralCategory {
            // Ordinals ('1st', '2nd') are not used by the wallet; returning
            // 'other' is the safe degradation rather than a wrong category.
            if (this.type === 'ordinal') return 'other';
            return selectPlural(this.locale, n);
        }

        resolvedOptions() {
            return {
                locale: this.locale,
                type: this.type,
                pluralCategories: pluralCategories(this.locale),
                minimumIntegerDigits: 1,
                minimumFractionDigits: 0,
                maximumFractionDigits: 3,
            };
        }

        static supportedLocalesOf(locales?: string | string[]): string[] {
            const list = Array.isArray(locales) ? locales : locales ? [locales] : [];
            return list.filter((l) => baseLanguage(l) in RULES);
        }
    }

    g.Intl.PluralRules = PluralRulesShim;
}
