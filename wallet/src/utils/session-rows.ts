// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One row per APP the holder has authenticated to, assembled from the three
 * places that know about it: the per-app session trail, the legacy trusted-app
 * rows, and the live sealed relay sessions.
 *
 * Shared, because two screens draw the same rows at different lengths. The
 * Access tab shows the most recent few and a count; `/sessions` shows all of
 * them with a search box. Two implementations would drift, and the count in the
 * section would eventually disagree with the list behind it.
 *
 * Keyed by serviceKey (the OIDC client id or enclave host), never by shared
 * rpId, so "Privasys Chat" and "Developer Platform" stay separate rows even
 * though both ride the privasys.id relying party.
 */

import type { TFunction } from 'i18next';

import type { SessionTrace } from '@/stores/service-sessions';
import { serviceHosts } from '@/stores/service-sessions';
import type { RelaySession } from '@/stores/sessions';
import type { TrustedApp } from '@/stores/trusted-apps';

/**
 * Compact "when" for a row subtitle.
 *
 * Counts go through plural keys rather than a bare suffix: "2 minutes" takes a
 * different form from "1 minute" in Polish, Welsh and Irish. Anything older
 * than a day falls back to a date rendered from the locale pack's own pattern,
 * not the device's.
 */
export function relativeWhen(ms: number, now: number, t: TFunction): string {
    const diff = now - ms;
    if (diff < 60_000) return t('time.justNow');
    if (diff < 3_600_000) return t('time.minutesAgo', { count: Math.floor(diff / 60_000) });
    if (diff < 86_400_000) return t('time.hoursAgo', { count: Math.floor(diff / 3_600_000) });
    return t('time.onDate', { when: new Date(ms) });
}

/** App name out of an rpId ("wasm-app-example.apps.privasys.org" -> the first label). */
export function appName(rpId: string): string {
    const dot = rpId.indexOf('.');
    return dot > 0 ? rpId.substring(0, dot) : rpId;
}

export interface SessionRow {
    key: string;
    name: string;
    /** Latest trace for this app, which drives the type label and subtitle. */
    trace?: SessionTrace;
    /** Legacy trusted-app row (pre-trace installs) backing this row. */
    app?: TrustedApp;
    session?: RelaySession;
    teeType: TrustedApp['teeType'];
    /** Sort key: most recently active first. */
    lastActiveMs: number;
}

export function buildSessionRows(
    traces: SessionTrace[],
    apps: TrustedApp[],
    sessions: RelaySession[],
    now: number,
): SessionRow[] {
    const live = sessions.filter((s) => s.expiresAt > now);
    const sessionByHost = new Map<string, RelaySession>();
    const sessionById = new Map<string, RelaySession>();
    for (const s of live) {
        sessionByHost.set(s.rpId, s);
        sessionById.set(s.sessionId, s);
    }

    // Group traces per app.
    const byService = new Map<string, SessionTrace[]>();
    for (const t of traces) {
        const list = byService.get(t.serviceKey);
        if (list) list.push(t);
        else byService.set(t.serviceKey, [t]);
    }

    const coveredHosts = new Set<string>();
    const coveredNames = new Set<string>();
    const coveredSessions = new Set<string>();
    const rows: SessionRow[] = [];

    for (const [key, list] of byService) {
        const latest = list[0]; // store is newest-first
        const hosts = serviceHosts(list);
        for (const h of hosts) coveredHosts.add(h);
        coveredNames.add(latest.displayName ?? appName(key));
        // Attach the live sealed session. Prefer the exact relay session id the
        // ceremony recorded on the trace: an IdP-brokered app keys its row by
        // the OIDC client_id while the relay session is keyed by rpId, so host
        // matching alone misses it and the session would orphan into a second,
        // duplicate row. Fall back to host matching for older traces with no id.
        let session: RelaySession | undefined;
        for (const t of list) {
            const s = t.sessionId ? sessionById.get(t.sessionId) : undefined;
            if (s) {
                session = s;
                coveredSessions.add(s.sessionId);
                break;
            }
        }
        if (!session) {
            for (const h of hosts) {
                const s = sessionByHost.get(h);
                if (s) {
                    session = s;
                    coveredSessions.add(s.sessionId);
                    break;
                }
            }
        }
        const att = list.find((t) => t.attestations?.length)?.attestations?.[0];
        rows.push({
            key,
            name: latest.displayName ?? appName(key),
            trace: latest,
            app: apps.find((a) => hosts.has(a.rpId)),
            session,
            teeType: att?.teeType ?? 'none',
            lastActiveMs: session ? Math.max(session.startedAt, latest.startedAt) : latest.startedAt,
        });
    }

    // Legacy trusted-app rows not covered by any trace yet (installs that
    // predate the per-app trail) keep their row so nothing disappears. A row
    // is covered when a trace touched its host, OR when a trace row carries the
    // same app name, so an app's OWN legacy row merges into its trace row once
    // it exists, while an unrelated app's trace (sharing only the privasys.id
    // rpId, now excluded from hosts) leaves it standing.
    for (const app of apps) {
        const appLabel = app.appName ?? appName(app.rpId);
        if (coveredHosts.has(app.rpId) || coveredNames.has(appLabel)) continue;
        const session = sessionByHost.get(app.rpId);
        if (session) coveredSessions.add(session.sessionId);
        rows.push({
            key: app.rpId,
            name: app.appName ?? appName(app.rpId),
            app,
            session,
            teeType: app.teeType,
            lastActiveMs: session ? session.startedAt : app.lastVerified * 1000,
        });
    }

    // Orphan live sessions (no trace, no trusted-app row, which is rare).
    for (const session of live) {
        if (coveredSessions.has(session.sessionId)) continue;
        rows.push({
            key: session.rpId,
            name: session.appName ?? appName(session.rpId),
            session,
            teeType: 'none',
            lastActiveMs: session.startedAt,
        });
    }

    rows.sort((a, b) => b.lastActiveMs - a.lastActiveMs);
    return rows;
}
