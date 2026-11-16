// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The app-neutral notification an attested app sends its users.
 *
 * The app supplies a kind from a closed list, an optional path on its own
 * host, and optional values someone presented to the holder, keyed by
 * canonical attribute keys. The host is never the app's: the platform names
 * the app's verified host (its live custom domain, or its platform hostname)
 * beside the notification, and a link that would land anywhere else is not
 * offered. The wallet draws presented values with its own labels and drops any
 * key outside the referential, so an app supplies values, never sentences.
 */

import { CANONICAL_KEYS } from '@/services/attributes';

export const APP_MESSAGE_TYPE = 'app-message';

/** The kinds the IdP knows. Anything else is shown generically. */
export type AppMessageKind = 'request' | 'invitation' | 'reminder' | 'response';
const KINDS: AppMessageKind[] = ['request', 'invitation', 'reminder', 'response'];

/** What the wallet reads out of an unsealed app-message payload. */
export interface AppMessageContent {
    kind?: AppMessageKind;
    path?: string;
    /** Canonical key to value, referential keys only, in the app's order. */
    presented: [string, string][];
}

const MAX_PATH = 512;
const MAX_VALUE = 200;

/** Read a payload, keeping only what the wallet will show or follow. */
export function readAppMessage(payload: Record<string, unknown> | null | undefined, kindHint?: string): AppMessageContent {
    const rawKind = typeof payload?.kind === 'string' ? payload.kind : kindHint;
    const kind = KINDS.includes(rawKind as AppMessageKind) ? (rawKind as AppMessageKind) : undefined;
    const rawPath = typeof payload?.path === 'string' ? payload.path : undefined;
    const path = rawPath && isSafePath(rawPath) ? rawPath : undefined;
    const presented: [string, string][] = [];
    const p = payload?.presented;
    if (p && typeof p === 'object' && !Array.isArray(p)) {
        for (const [key, value] of Object.entries(p as Record<string, unknown>)) {
            if (!CANONICAL_KEYS.has(key) || typeof value !== 'string') continue;
            const v = value.trim().slice(0, MAX_VALUE);
            if (v) presented.push([key, v]);
        }
    }
    return { kind, path, presented };
}

/** A path on the app's own host: rooted, bounded, and never "//host". */
function isSafePath(path: string): boolean {
    return (
        path.startsWith('/') &&
        !path.startsWith('//') &&
        path.length <= MAX_PATH &&
        !/[\\\s]/.test(path)
    );
}

/** A plain DNS name, as the platform names an app's host. */
const HOST_SHAPE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

/**
 * The link to open, or undefined. Only https, only on the host the platform
 * named, and only when the URL parsed back still has that host: a path that
 * smuggled in another authority is refused rather than repaired.
 */
export function appMessageLink(appHost: string | undefined, path: string | undefined): string | undefined {
    const host = (appHost ?? '').toLowerCase();
    if (!host || !HOST_SHAPE.test(host) || !path || !isSafePath(path)) return undefined;
    const url = `https://${host}${path}`;
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== host || parsed.port !== '' ||
            parsed.username !== '' || parsed.password !== '') {
            return undefined;
        }
    } catch {
        return undefined;
    }
    return url;
}
