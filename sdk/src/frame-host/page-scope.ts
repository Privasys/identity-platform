// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

/**
 * Which page this frame serves and which session a message reaches: the
 * page's platform from its origin, the session key a message names, and
 * whether the identity provider accepts the page for the client.
 */

import { parsePlatforms, type PlatformEntry } from '../platforms';
import { RP_ID, SessionManager, type PlatformScope, type SessionKey } from '../session';
import type { AuthSession } from '../types';

export const sessions = new SessionManager();

// What the identity provider said about a page and a client, for this
// document's life. Only a yes is kept: a refusal or a failed lookup is asked
// again, so registering an origin takes effect without a reload.
export const pageVerdicts = new Set<string>();

/**
 * Whether the page at `pageOrigin` is one `clientId` registered: its
 * redirect URIs' origins and its allowed origins, the list a sign-in with no
 * redirect is checked against. The identity provider answers, logs a page it
 * does not know, and refuses it once that check is enforced. A lookup that
 * fails is a no: nothing else here works without the identity provider.
 */
export async function pageIsClients(clientId: string, pageOrigin: string): Promise<boolean> {
    const key = `${clientId}|${pageOrigin}`;
    if (pageVerdicts.has(key)) return true;
    try {
        const u = new URL('/session/client-origin', globalThis.location.origin);
        u.searchParams.set('client_id', clientId);
        u.searchParams.set('origin', pageOrigin);
        const resp = await fetch(u.toString(), { cache: 'no-store' });
        if (!resp.ok) return false;
        const body = await resp.json().catch(() => null);
        if (body?.allowed !== true) return false;
        pageVerdicts.add(key);
        return true;
    } catch {
        return false;
    }
}

// ── The page's platform ──────────────────────────────────────────────────
//
// Every page under one registrable domain shares this frame's storage, and
// pages of more than one platform can live under one domain (a production
// platform and a test platform, say). The identity provider publishes which
// domains belong to which platform (platforms.ts places a page).

export const PLATFORM_LIST_TTL_MS = 5 * 60_000;
let platformList: { at: number; list: PlatformEntry[] } | null = null;

/** The identity provider's platform list, or null when it cannot be read. */
export async function loadPlatforms(): Promise<PlatformEntry[] | null> {
    if (platformList && Date.now() - platformList.at < PLATFORM_LIST_TTL_MS) return platformList.list;
    try {
        const resp = await fetch(new URL('/wallet/platforms', globalThis.location.origin).toString(), { cache: 'no-store' });
        if (resp.ok) {
            const list = parsePlatforms(await resp.json().catch(() => null));
            if (list) {
                platformList = { at: Date.now(), list };
                return list;
            }
        }
    } catch { /* unreadable: the last good list, if any */ }
    return platformList?.list ?? null;
}

/**
 * The session key a message names: the page's platform, from the origin the
 * browser reports for it and never from anything the page says, and the
 * client the message names. Null when the platform cannot be told or the
 * message names no client: such a message reaches no session.
 */
export function messageKey(scope: PlatformScope | null, data: { clientId?: unknown }): SessionKey | null {
    if (!scope) return null;
    if (typeof data.clientId !== 'string' || !data.clientId) return null;
    return { platform: scope.platform, rpId: RP_ID, clientId: data.clientId };
}

/** How the person of a stored session signed in. */
export function methodOf(session: AuthSession): 'wallet' | 'passkey' | 'social' {
    return session.method ?? (session.wallet ? 'wallet' : 'passkey');
}

/**
 * The stored session this page may use, or undefined. A session belongs to a
 * client, and only that client's own pages are given it: every page under one
 * registrable domain shares this frame's storage, so without this a page
 * could take another app's session by naming its client.
 */
export async function sessionForPage(key: SessionKey | null, pageOrigin: string): Promise<AuthSession | undefined> {
    const session = key ? sessions.get(key) : undefined;
    if (!session) return undefined;
    return (await pageIsClients(key!.clientId, pageOrigin)) ? session : undefined;
}
