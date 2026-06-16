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

import * as Storage from '@/utils/storage';
import { ATTRIBUTE_MAP } from '@/services/attributes';

/** One option in an enumerated value set. */
export interface ValueOption {
    value: string;
    label: string;
}

/** Base URL of the Privasys IdP (matches identity.ts / recovery-api.ts). */
const IDP_BASE = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

const memoryCache: Record<string, ValueOption[]> = {};

function cacheKey(attrKey: string): string {
    return `v1-valueset-${attrKey}`;
}

function resolveUrl(valuesUrl: string): string {
    if (/^https?:\/\//i.test(valuesUrl)) return valuesUrl;
    return `${IDP_BASE}${valuesUrl.startsWith('/') ? '' : '/'}${valuesUrl}`;
}

/**
 * Return the allowed values for an enumerated attribute, or [] if the attribute
 * has no value set. Tries: in-memory cache → network → persisted cache.
 */
export async function getAttributeValues(attrKey: string): Promise<ValueOption[]> {
    if (memoryCache[attrKey]) return memoryCache[attrKey];

    const valuesUrl = ATTRIBUTE_MAP[attrKey]?.valuesUrl;
    if (!valuesUrl) return [];

    try {
        const resp = await fetch(resolveUrl(valuesUrl), { headers: { Accept: 'application/json' } });
        if (resp.ok) {
            const data: { values?: ValueOption[] } = await resp.json();
            const values = (data.values ?? []).filter((v) => v.value && v.label);
            if (values.length > 0) {
                memoryCache[attrKey] = values;
                Storage.setItemAsync(cacheKey(attrKey), JSON.stringify(values)).catch(() => {});
                return values;
            }
        }
    } catch {
        // fall through to the persisted cache
    }

    // Offline / fetch failure: use the last good list if we have one.
    try {
        const raw = await Storage.getItemAsync(cacheKey(attrKey));
        if (raw) {
            const values = JSON.parse(raw) as ValueOption[];
            memoryCache[attrKey] = values;
            return values;
        }
    } catch {
        // ignore
    }
    return [];
}

/** Human-readable label for a value within an attribute's set (sync, cache-only). */
export function cachedValueLabel(attrKey: string, value: string): string {
    return memoryCache[attrKey]?.find((v) => v.value === value)?.label ?? value;
}
