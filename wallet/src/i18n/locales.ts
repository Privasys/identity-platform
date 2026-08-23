// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The languages the wallet ships: the 24 official languages of the European
 * Union plus Welsh.
 *
 * Only `en-GB` is compiled into the binary. Everything else is a locale pack
 * fetched once and cached (see i18n/packs.ts), so this table is the list of
 * packs that may exist, not the list currently on the device.
 *
 * Names are ENDONYMS: a language is listed the way its own speakers write it,
 * because the picker has to be readable by someone who cannot yet read the
 * app. Same convention as shared/referential/locale.json, which the profile's
 * `locale` attribute already uses.
 */

export interface LocaleMeta {
    /** BCP-47 tag used as the pack name and the i18next language. */
    tag: string;
    /** The language's name in itself, for the picker. */
    endonym: string;
    /** English name, for logs, support and the store listing matrix. */
    english: string;
    /** False for Welsh, which is not an EU official language. */
    euOfficial: boolean;
}

/** The source locale, compiled in and always available. */
export const FALLBACK_LOCALE = 'en-GB';

export const SUPPORTED_LOCALES: readonly LocaleMeta[] = [
    { tag: 'en-GB', endonym: 'English', english: 'English', euOfficial: true },
    { tag: 'bg', endonym: 'Български', english: 'Bulgarian', euOfficial: true },
    { tag: 'cs', endonym: 'Čeština', english: 'Czech', euOfficial: true },
    { tag: 'da', endonym: 'Dansk', english: 'Danish', euOfficial: true },
    { tag: 'de', endonym: 'Deutsch', english: 'German', euOfficial: true },
    { tag: 'el', endonym: 'Ελληνικά', english: 'Greek', euOfficial: true },
    { tag: 'es', endonym: 'Español', english: 'Spanish', euOfficial: true },
    { tag: 'et', endonym: 'Eesti', english: 'Estonian', euOfficial: true },
    { tag: 'fi', endonym: 'Suomi', english: 'Finnish', euOfficial: true },
    { tag: 'fr', endonym: 'Français', english: 'French', euOfficial: true },
    { tag: 'ga', endonym: 'Gaeilge', english: 'Irish', euOfficial: true },
    { tag: 'hr', endonym: 'Hrvatski', english: 'Croatian', euOfficial: true },
    { tag: 'hu', endonym: 'Magyar', english: 'Hungarian', euOfficial: true },
    { tag: 'it', endonym: 'Italiano', english: 'Italian', euOfficial: true },
    { tag: 'lt', endonym: 'Lietuvių', english: 'Lithuanian', euOfficial: true },
    { tag: 'lv', endonym: 'Latviešu', english: 'Latvian', euOfficial: true },
    { tag: 'mt', endonym: 'Malti', english: 'Maltese', euOfficial: true },
    { tag: 'nl', endonym: 'Nederlands', english: 'Dutch', euOfficial: true },
    { tag: 'pl', endonym: 'Polski', english: 'Polish', euOfficial: true },
    { tag: 'pt', endonym: 'Português', english: 'Portuguese', euOfficial: true },
    { tag: 'ro', endonym: 'Română', english: 'Romanian', euOfficial: true },
    { tag: 'sk', endonym: 'Slovenčina', english: 'Slovak', euOfficial: true },
    { tag: 'sl', endonym: 'Slovenščina', english: 'Slovenian', euOfficial: true },
    { tag: 'sv', endonym: 'Svenska', english: 'Swedish', euOfficial: true },
    { tag: 'cy', endonym: 'Cymraeg', english: 'Welsh', euOfficial: false },
];

const BY_TAG = new Map(SUPPORTED_LOCALES.map((l) => [l.tag.toLowerCase(), l]));
/** Base language to tag, so 'en' finds 'en-GB' and 'de-AT' finds 'de'. */
const BY_BASE = new Map(
    SUPPORTED_LOCALES.map((l) => [l.tag.split('-')[0].toLowerCase(), l]),
);

export function localeMeta(tag: string): LocaleMeta | undefined {
    if (!tag) return undefined;
    return BY_TAG.get(tag.toLowerCase()) ?? BY_BASE.get(tag.split(/[-_]/)[0].toLowerCase());
}

/**
 * Resolve any BCP-47 tag to a locale we actually ship.
 *
 * Region is dropped rather than rejected, because the OS reports what the
 * user set on their phone, not what we publish: `de-AT`, `de-CH` and `de-DE`
 * all become `de`, `pt-BR` becomes `pt`, and `en-US` becomes `en-GB`. That
 * last one is deliberate. American English is closer to British English than
 * to no translation at all, and the wallet's copy is UK English by house
 * style, so serving it is right even where the spelling differs.
 *
 * Anything we do not ship falls back to `en-GB`.
 */
export function negotiateLocale(preferred: string | undefined | null): string {
    return localeMeta(preferred ?? '')?.tag ?? FALLBACK_LOCALE;
}

/** Whether `tag` needs a downloaded pack, or is the compiled-in fallback. */
export function needsPack(tag: string): boolean {
    return negotiateLocale(tag) !== FALLBACK_LOCALE;
}
