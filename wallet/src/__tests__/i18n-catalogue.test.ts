// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Guards on the translation catalogue itself.
 *
 * Translations fail quietly. A missing key renders as the key, a stale digest
 * silently pins users to en-GB, a missing plural form falls back to the wrong
 * grammar, and none of that is visible to anyone reviewing in English. These
 * checks are the substitute for a reviewer who reads all 25 languages.
 */

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { EN_GB_FORMATS } from '@/i18n/formatters';
import { FALLBACK_LOCALE, SUPPORTED_LOCALES } from '@/i18n/locales';
import { I18N_MANIFEST } from '@/i18n/manifest';
import { pluralCategories } from '@/i18n/plural-rules';

const LOCALES_DIR = resolve(__dirname, '..', 'i18n', 'locales');

type Json = Record<string, unknown>;

function readLocale(tag: string): Json {
    return JSON.parse(readFileSync(join(LOCALES_DIR, `${tag}.json`), 'utf8')) as Json;
}

function localeFiles(): string[] {
    return readdirSync(LOCALES_DIR)
        .filter((f) => f.endsWith('.json'))
        .map((f) => f.replace(/\.json$/, ''))
        .sort();
}

/**
 * Flatten to dotted paths. Plural suffixes are stripped so `foo_one` and
 * `foo_other` collapse to `foo`: languages legitimately differ in how many
 * forms they need, so comparing raw keys would flag every Polish file.
 */
function keyPaths(obj: Json, prefix = ''): Set<string> {
    const out = new Set<string>();
    for (const [k, v] of Object.entries(obj)) {
        const path = prefix ? `${prefix}.${k}` : k;
        if (v && typeof v === 'object' && !Array.isArray(v)) {
            for (const nested of keyPaths(v as Json, path)) out.add(nested);
        } else {
            out.add(path.replace(/_(zero|one|two|few|many|other)$/, ''));
        }
    }
    return out;
}

/** Every leaf string value, with its path, for content checks. */
function leaves(obj: Json, prefix = ''): [string, string][] {
    const out: [string, string][] = [];
    for (const [k, v] of Object.entries(obj)) {
        const path = prefix ? `${prefix}.${k}` : k;
        if (typeof v === 'string') out.push([path, v]);
        else if (Array.isArray(v)) {
            v.forEach((item, i) => {
                if (typeof item === 'string') out.push([`${path}[${i}]`, item]);
            });
        } else if (v && typeof v === 'object') {
            out.push(...leaves(v as Json, path));
        }
    }
    return out;
}

/** `{{name}}` and `{{name, formatter}}` placeholders in a string. */
function placeholders(s: string): Set<string> {
    const out = new Set<string>();
    for (const m of s.matchAll(/\{\{\s*([A-Za-z0-9_]+)\s*(?:,[^}]*)?\}\}/g)) out.add(m[1]);
    return out;
}

const source = readLocale(FALLBACK_LOCALE);
const sourceKeys = keyPaths(source);
const translations = localeFiles().filter((t) => t !== FALLBACK_LOCALE);

describe('source catalogue (en-GB)', () => {
    it('exists and is not empty', () => {
        expect(sourceKeys.size).toBeGreaterThan(0);
    });

    it('carries a format block matching the compiled-in fallback', () => {
        // packs.ts reads `format` from each pack; en-GB's copy in code is the
        // ultimate fallback. If the two drift, dates render inconsistently
        // depending on whether a pack loaded.
        expect(source.format).toEqual(EN_GB_FORMATS as unknown as Json);
    });

    it('uses no em-dashes', () => {
        const offenders = leaves(source)
            .filter(([, v]) => v.includes('—'))
            .map(([k]) => k);
        expect(offenders).toEqual([]);
    });

    it('has no empty strings', () => {
        const empty = leaves(source).filter(([, v]) => v.trim() === '').map(([k]) => k);
        expect(empty).toEqual([]);
    });
});

describe('locale files', () => {
    it('only contains locales the wallet declares as supported', () => {
        const declared = new Set(SUPPORTED_LOCALES.map((l) => l.tag));
        const undeclared = localeFiles().filter((t) => !declared.has(t));
        expect(undeclared).toEqual([]);
    });

    // `describe.each` on an empty list throws, so guard while translations
    // are still being added.
    if (translations.length) {
        describe.each(translations)('%s', (tag) => {
            const locale = readLocale(tag);

            it('has no keys the source lacks', () => {
                const orphans = [...keyPaths(locale)].filter((k) => !sourceKeys.has(k));
                expect(orphans).toEqual([]);
            });

            it('is missing no keys the source has', () => {
                const have = keyPaths(locale);
                const missing = [...sourceKeys].filter((k) => !have.has(k));
                expect(missing).toEqual([]);
            });

            it('supplies every plural form its language needs', () => {
                const needed = pluralCategories(tag);
                const gaps: string[] = [];
                for (const [path] of leaves(source)) {
                    const m = path.match(/^(.*)_(?:zero|one|two|few|many|other)$/);
                    if (!m) continue;
                    for (const cat of needed) {
                        const key = `${m[1]}_${cat}`;
                        if (!leaves(locale).some(([p]) => p === key)) gaps.push(key);
                    }
                }
                expect([...new Set(gaps)]).toEqual([]);
            });

            it('preserves every interpolation placeholder', () => {
                // A dropped {{count}} is invisible in review and renders a
                // sentence with a hole in it.
                const src = new Map(leaves(source));
                const mismatches: string[] = [];
                for (const [path, value] of leaves(locale)) {
                    const original = src.get(path) ?? src.get(path.replace(/_(zero|one|two|few|many|other)$/, '_other'));
                    if (!original) continue;
                    const want = placeholders(original);
                    const got = placeholders(value);
                    for (const ph of want) {
                        if (!got.has(ph)) mismatches.push(`${path}: missing {{${ph}}}`);
                    }
                    for (const ph of got) {
                        if (!want.has(ph)) mismatches.push(`${path}: unexpected {{${ph}}}`);
                    }
                }
                expect(mismatches).toEqual([]);
            });

            it('carries a complete format block', () => {
                const f = locale.format as Record<string, unknown>;
                expect(f).toBeDefined();

                const lengths: [string, number][] = [
                    ['months', 12],
                    ['monthsShort', 12],
                    ['days', 7],
                    ['daysShort', 7],
                ];
                for (const [field, want] of lengths) {
                    const value = f[field];
                    expect(Array.isArray(value)).toBe(true);
                    expect((value as string[]).length).toBe(want);
                }

                for (const field of ['date', 'dateLong', 'time']) {
                    expect(typeof f[field]).toBe('string');
                }

                // The joining pattern must keep both slots or one half is lost.
                expect(String(f.dateTime)).toContain('{{date}}');
                expect(String(f.dateTime)).toContain('{{time}}');
            });

            it('uses no em-dashes', () => {
                const offenders = leaves(locale)
                    .filter(([, v]) => v.includes('—'))
                    .map(([k]) => k);
                expect(offenders).toEqual([]);
            });

            it('leaves no string untranslated by accident', () => {
                // A handful of values are legitimately identical across
                // languages (product names, "OK"). A file that is MOSTLY
                // identical to English has not really been translated.
                const src = new Map(leaves(source));
                const values = leaves(locale).filter(([p]) => !p.startsWith('format'));
                const same = values.filter(([p, v]) => src.get(p) === v);
                expect(same.length / Math.max(values.length, 1)).toBeLessThan(0.5);
            });
        });
    }
});

describe('pack manifest', () => {
    it('lists exactly the downloadable locale files', () => {
        expect(Object.keys(I18N_MANIFEST.digests).sort()).toEqual(translations);
    });

    it('is up to date with the locale files on disk', () => {
        // The digest rule is restated here rather than imported from
        // scripts/gen-i18n-manifest.mjs, which jest cannot load as ESM. That
        // makes this an INDEPENDENT reimplementation: it catches a stale
        // manifest and a broken generator alike. The two must be changed
        // together, and the generator's header says so.
        const digests: Record<string, string> = {};
        for (const tag of translations) {
            digests[tag] = createHash('sha256')
                .update(readFileSync(join(LOCALES_DIR, `${tag}.json`)))
                .digest('hex');
        }
        const version = createHash('sha256')
            .update(Object.entries(digests).map(([t, d]) => `${t}:${d}`).join('\n'))
            .digest('hex')
            .slice(0, 16);

        // A stale manifest means every pack fails its digest check and every
        // user silently stays on English. Run `npm run i18n:manifest`.
        expect(digests).toEqual({ ...I18N_MANIFEST.digests });
        expect(version).toBe(I18N_MANIFEST.version);
    });
});
