// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * i18next wiring.
 *
 * Initialisation is SYNCHRONOUS and always succeeds: the instance starts on
 * the compiled-in en-GB bundle, so the first frame renders real copy with no
 * await, no spinner and no network. The user's actual language is then
 * loaded in the background and swapped in when it verifies.
 *
 * That ordering is deliberate. Account recovery is the one flow a user
 * reaches on a fresh install, possibly offline, possibly in a hurry, and it
 * must never be blocked on a CDN. English copy is a far better failure mode
 * than a blank screen.
 *
 * Language is resolved from, in order:
 *   1. the explicit Settings -> Language override
 *   2. the profile's `locale` attribute (device-filled on first run)
 *   3. the OS locale
 *   4. en-GB
 */

import i18next, { type i18n as I18nInstance } from 'i18next';
import { initReactI18next } from 'react-i18next';

import enGB from './locales/en-GB.json';
import {
    EN_GB_FORMATS,
    formatDate,
    formatDateTime,
    formatTechnical,
    formatTime,
    formatCount,
    type LocaleFormats,
} from './formatters';
import { FALLBACK_LOCALE, negotiateLocale } from './locales';
import { loadPack, purgeStalePacks } from './packs';
import { installPluralRulesShim } from './plural-rules';

/** i18next resolves plurals through Intl.PluralRules, which Hermes lacks. */
installPluralRulesShim();

/** The single namespace; screens are namespaced by key prefix instead. */
const NS = 'translation';

/** Per-locale date patterns and month names, keyed by tag. */
const FORMATS: Record<string, LocaleFormats> = { [FALLBACK_LOCALE]: EN_GB_FORMATS };

let activeLocale: string = FALLBACK_LOCALE;

/** Formats for the language currently displayed. */
export function currentFormats(): LocaleFormats {
    return FORMATS[activeLocale] ?? EN_GB_FORMATS;
}

/** The language currently displayed, always a tag we ship. */
export function currentLocale(): string {
    return activeLocale;
}

function registerFormatters(i18n: I18nInstance): void {
    const f = i18n.services.formatter;
    if (!f) return;
    // `lng` is ignored on purpose: formats follow the APP language, which is
    // what `activeLocale` tracks, not whatever i18next was handed.
    f.add('date', (value) => formatDate(value, currentFormats()));
    f.add('dateLong', (value) => formatDate(value, currentFormats(), true));
    f.add('time', (value) => formatTime(value, currentFormats()));
    f.add('datetime', (value) => formatDateTime(value, currentFormats()));
    f.add('datetimeLong', (value) => formatDateTime(value, currentFormats(), true));
    // Hashes, DIDs, measurements: rendered verbatim, never grouped or shaped.
    f.add('technical', (value) => formatTechnical(value));
    f.add('count', (value) => formatCount(value));
}

let initialised = false;

/**
 * Bring i18next up on en-GB. Safe to call more than once.
 */
export function initI18n(): I18nInstance {
    if (initialised) return i18next;
    initialised = true;

    void i18next.use(initReactI18next).init({
        lng: FALLBACK_LOCALE,
        fallbackLng: FALLBACK_LOCALE,
        defaultNS: NS,
        ns: [NS],
        resources: { [FALLBACK_LOCALE]: { [NS]: enGB } },
        // Values are escaped for HTML by default, which mangles apostrophes
        // and quotes in a React Native app that never renders HTML.
        interpolation: { escapeValue: false },
        returnNull: false,
        // A missing key should show the key, not an empty gap, so that a gap
        // in a pack is obvious in review rather than invisible.
        parseMissingKeyHandler: (key) => key,
    });

    registerFormatters(i18next);
    return i18next;
}

/**
 * Why a language could not be applied.
 *
 * The two cases mean very different things and must not share a message.
 * `unavailable` is "we could not get it", a transient annoyance. `rejected`
 * is "what was served is not what this build is signed to accept", which is
 * either a corrupted download or someone tampering with the pack, and the
 * user is entitled to be told that rather than being shown a network error.
 */
export type ApplyFailure = 'unavailable' | 'rejected';
export type ApplyResult = { ok: true } | { ok: false; reason: ApplyFailure };

const APPLIED: ApplyResult = { ok: true };

/**
 * Switch the displayed language, downloading its pack if needed.
 *
 * On failure the previous language stays up and the reason is returned.
 * Callers should surface it, never treat it as a silent no-op.
 */
export async function applyLocale(tag: string | null | undefined): Promise<ApplyResult> {
    initI18n();
    const target = negotiateLocale(tag ?? undefined);

    if (target === activeLocale) return APPLIED;

    if (target === FALLBACK_LOCALE) {
        activeLocale = FALLBACK_LOCALE;
        await i18next.changeLanguage(FALLBACK_LOCALE);
        return APPLIED;
    }

    const result = await loadPack(target);
    if (!result.ok) {
        // A pack that fails its digest check, or parses to something that is
        // not a resource bundle, was not produced by the build this app
        // trusts. Everything else is "could not fetch it".
        const rejected = result.reason === 'digest-mismatch' || result.reason === 'malformed';
        return { ok: false, reason: rejected ? 'rejected' : 'unavailable' };
    }

    // Every locale file, en-GB included, carries a `format` block alongside
    // its copy so all packs have one shape and key-parity checking is a plain
    // set comparison. A pack missing it would render en-GB dates under
    // translated copy, so treat that as malformed rather than half-applying.
    const format = (result.resources as { format?: LocaleFormats }).format;
    if (!format || !Array.isArray(format.months) || format.months.length !== 12) {
        return { ok: false, reason: 'rejected' };
    }

    FORMATS[target] = format;
    i18next.addResourceBundle(target, NS, result.resources, true, true);
    activeLocale = target;
    await i18next.changeLanguage(target);

    if (result.from === 'network') purgeStalePacks();
    return APPLIED;
}

export { i18next };
