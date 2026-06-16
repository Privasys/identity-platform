// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Curated BCP-47 locale tags for the `locale` canonical attribute.
 *
 * The `locale` attribute is meant to be a standard language tag (BCP-47,
 * built on ISO 639 language + optional ISO 3166-1 region), not free text. The
 * wallet offers this short curated list in manual entry and normalises
 * provider-sourced values (which may arrive as `en_US`, `EN-gb`, etc.) to a
 * canonical tag from this list.
 */

export interface LocaleOption {
    /** Canonical BCP-47 tag, e.g. "en-GB". */
    tag: string;
    /** Human-readable label (endonym + English where useful). */
    label: string;
}

export const LOCALES: LocaleOption[] = [
    { tag: 'en', label: 'English' },
    { tag: 'en-GB', label: 'English (United Kingdom)' },
    { tag: 'en-US', label: 'English (United States)' },
    { tag: 'fr', label: 'Français (French)' },
    { tag: 'fr-FR', label: 'Français (France)' },
    { tag: 'de', label: 'Deutsch (German)' },
    { tag: 'es', label: 'Español (Spanish)' },
    { tag: 'es-ES', label: 'Español (España)' },
    { tag: 'pt', label: 'Português (Portuguese)' },
    { tag: 'pt-BR', label: 'Português (Brasil)' },
    { tag: 'it', label: 'Italiano (Italian)' },
    { tag: 'nl', label: 'Nederlands (Dutch)' },
    { tag: 'pl', label: 'Polski (Polish)' },
    { tag: 'sv', label: 'Svenska (Swedish)' },
    { tag: 'da', label: 'Dansk (Danish)' },
    { tag: 'no', label: 'Norsk (Norwegian)' },
    { tag: 'fi', label: 'Suomi (Finnish)' },
    { tag: 'cs', label: 'Čeština (Czech)' },
    { tag: 'el', label: 'Ελληνικά (Greek)' },
    { tag: 'tr', label: 'Türkçe (Turkish)' },
    { tag: 'ru', label: 'Русский (Russian)' },
    { tag: 'uk', label: 'Українська (Ukrainian)' },
    { tag: 'ar', label: 'العربية (Arabic)' },
    { tag: 'he', label: 'עברית (Hebrew)' },
    { tag: 'hi', label: 'हिन्दी (Hindi)' },
    { tag: 'zh', label: '中文 (Chinese)' },
    { tag: 'zh-CN', label: '中文 (简体, Simplified)' },
    { tag: 'zh-TW', label: '中文 (繁體, Traditional)' },
    { tag: 'ja', label: '日本語 (Japanese)' },
    { tag: 'ko', label: '한국어 (Korean)' },
];

const TAG_BY_LOWER: Record<string, string> = Object.fromEntries(
    LOCALES.map((l) => [l.tag.toLowerCase(), l.tag]),
);

/** Human-readable label for a locale tag, falling back to the tag itself. */
export function localeLabel(tag: string): string {
    return LOCALES.find((l) => l.tag === tag)?.label ?? tag;
}

/**
 * Normalise a raw locale string to a canonical BCP-47 tag from LOCALES.
 * Handles `_` separators and casing (e.g. `en_us` -> `en-US`). Falls back to
 * the base language tag if the exact region isn't curated, else returns the
 * cleaned input unchanged.
 */
export function normalizeLocale(raw: string): string {
    if (!raw) return raw;
    const cleaned = raw.replace(/_/g, '-').trim();
    const exact = TAG_BY_LOWER[cleaned.toLowerCase()];
    if (exact) return exact;
    const base = cleaned.split('-')[0]?.toLowerCase() ?? '';
    if (base && TAG_BY_LOWER[base]) return TAG_BY_LOWER[base];
    return cleaned;
}
