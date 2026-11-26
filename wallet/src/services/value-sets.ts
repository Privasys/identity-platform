// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Enumerated attribute value sets, fetched from the IdP on demand.
 *
 * Some canonical attributes (e.g. `locale`, and later `nationality`) are
 * constrained to a list of allowed values. That list is part of the shared
 * referential and is hosted by the IdP (see canonical-attributes.json
 * `valuesUrl` + the IdP's /referential/<name>.json). The wallet fetches it
 * lazily and caches it, rather than bundling its own copy — one source of
 * truth, and the app stays light + updatable without a release.
 */

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import * as Storage from '@/utils/storage';
import { ATTRIBUTE_MAP } from '@/services/attributes';
import { currentLocale } from '@/i18n';

/** One option in an enumerated value set. */
export interface ValueOption {
    value: string;
    label: string;
}

/** Base URL of the Privasys IdP (matches identity.ts / recovery-api.ts). */
const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

const memoryCache: Record<string, ValueOption[]> = {};

function cacheKey(attrKey: string, lang: string): string {
    return `v1-valueset-${attrKey}-${lang}`;
}

function resolveUrl(valuesUrl: string, lang: string): string {
    const url = /^https?:\/\//i.test(valuesUrl)
        ? valuesUrl
        : `${IDP_BASE}${valuesUrl.startsWith('/') ? '' : '/'}${valuesUrl}`;
    return `${url}${url.includes('?') ? '&' : '?'}lang=${encodeURIComponent(lang)}`;
}

/**
 * Return the allowed values for an enumerated attribute, or [] if the attribute
 * has no value set. Tries: in-memory cache → network → persisted cache.
 *
 * The values are codes (ISO 3166-1, BCP 47), stored and disclosed as such;
 * the labels are their long names in `lang`, the wallet's language. The IdP
 * serves one copy per language (?lang=, English when it has none), so the
 * wallet holds only the list it shows.
 */
export async function getAttributeValues(attrKey: string, lang = currentLocale()): Promise<ValueOption[]> {
    const key = `${attrKey}:${lang}`;
    if (memoryCache[key]) return memoryCache[key];

    const valuesUrl = ATTRIBUTE_MAP[attrKey]?.valuesUrl;
    if (!valuesUrl) return [];

    try {
        const resp = await fetch(resolveUrl(valuesUrl, lang), { headers: { Accept: 'application/json' } });
        if (resp.ok) {
            const data: { values?: ValueOption[] } = await resp.json();
            const values = (data.values ?? []).filter((v) => v.value && v.label);
            if (values.length > 0) {
                memoryCache[key] = values;
                Storage.setItemAsync(cacheKey(attrKey, lang), JSON.stringify(values)).catch(() => {});
                return values;
            }
        }
    } catch {
        // fall through to the persisted cache
    }

    // Offline / fetch failure: use the last good list if we have one.
    try {
        const raw = await Storage.getItemAsync(cacheKey(attrKey, lang));
        if (raw) {
            const values = JSON.parse(raw) as ValueOption[];
            memoryCache[key] = values;
            return values;
        }
    } catch {
        // ignore
    }
    return [];
}

/** Whether an attribute's value is a code from a list (country, language). */
export function isCodedAttribute(attrKey: string): boolean {
    return !!ATTRIBUTE_MAP[attrKey]?.valuesUrl;
}

/**
 * The long name of a coded value in the wallet's language ("FRA" → "France",
 * "Frankreich", ...), or the code itself until the list has loaded or when it
 * is not on it. Non-coded attributes come back unchanged.
 */
export function useValueLabel(attrKey: string, value: string): string {
    const { i18n } = useTranslation();
    const lang = i18n.language;
    const coded = isCodedAttribute(attrKey);
    const [options, setOptions] = useState<ValueOption[] | null>(
        () => (coded ? memoryCache[`${attrKey}:${lang}`] ?? null : null),
    );
    useEffect(() => {
        if (!coded) return;
        let live = true;
        void getAttributeValues(attrKey, lang).then((v) => { if (live) setOptions(v); });
        return () => { live = false; };
    }, [attrKey, lang, coded]);
    if (!coded || !options) return value;
    const v = value.trim().toUpperCase();
    return options.find((o) => o.value.toUpperCase() === v)?.label ?? value;
}

