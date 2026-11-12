// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Where a document's chip is, so the holder can be told where to lay the phone.
 *
 * Nothing prescribes where an issuer puts the chip, and no public list exists.
 * So this is a list of our own, and every rule in it rests on a source that
 * says so for that document: an entry is a fact someone can check, never a
 * guess from a neighbouring series or a single specimen. A document with no
 * rule gets the order to try, which is always right, only slower.
 *
 * The rules are data (chip-placement.data.json). A newer signed copy can be
 * fetched from privasys.id (services/chip-placement-remote.ts), so a position
 * can be corrected without a release. That copy carries position CODES only:
 * the words and drawings shown for each code are the wallet's own, so the
 * served file cannot put text of its choosing on screen.
 *
 * Kept free of native modules so it can be tested on its own.
 */

import builtIn from './chip-placement.data.json';

export const PLACEMENT_SCHEMA = 'privasys.wallet.chip-placement/1';

export type PlacementDocument = 'passport' | 'id-card';

/** The places the wallet has words and a drawing for. */
export const CHIP_POSITIONS = ['back-cover', 'front-cover', 'photo-page', 'card'] as const;
export type ChipPosition = (typeof CHIP_POSITIONS)[number];

export interface PlacementRule {
    document: PlacementDocument;
    /** Issuing state as the machine readable zone writes it (Germany is `D`). */
    country: string;
    /** First and last month of issue this holds for, `YYYY-MM`. Open when absent. */
    issuedFrom?: string;
    issuedTo?: string;
    /** Where to try, in order. */
    positions: ChipPosition[];
    /** The page that states it. */
    source: string;
}

export interface PlacementDoc {
    schema: string;
    /** ISO time. A copy is only taken over a newer one. */
    issuedAt: string;
    /** Years a document is valid for, by issuing state, when it is not 10 and 5. */
    validity?: Record<string, { adult?: number; child?: number }>;
    rules: PlacementRule[];
}

export interface Placement {
    /** Where to try, in order: what a rule says first, then everywhere else. Never empty. */
    positions: ChipPosition[];
    /** False when no rule matched and this is the general order. */
    known: boolean;
}

/** The order that finds any chip: used whenever nothing better is known. */
const ORDER_TO_TRY: Record<PlacementDocument, ChipPosition[]> = {
    passport: ['back-cover', 'photo-page', 'front-cover'],
    'id-card': ['card'],
};

/** How far the estimated issue date may be out, either way. */
const ESTIMATE_SLACK_MONTHS = 12;

const MONTH = /^(\d{4})-(0[1-9]|1[0-2])$/;

/** A month as a count of months, so two can be compared and subtracted. */
function monthIndex(value: string | undefined): number | null {
    const m = value ? MONTH.exec(value) : null;
    return m ? Number(m[1]) * 12 + (Number(m[2]) - 1) : null;
}

/**
 * Check a document read from disk or the network. Returns it typed, or null.
 *
 * Strict on purpose: a rule this build cannot draw (a position it has no words
 * for) is dropped rather than half-shown, and a document with the wrong schema
 * is refused whole, which is what stops a different signed document being
 * served in this one's place.
 */
export function parsePlacementDoc(input: unknown): PlacementDoc | null {
    if (!input || typeof input !== 'object') return null;
    const doc = input as Record<string, unknown>;
    if (doc.schema !== PLACEMENT_SCHEMA) return null;
    if (typeof doc.issuedAt !== 'string' || !Number.isFinite(Date.parse(doc.issuedAt))) return null;
    if (!Array.isArray(doc.rules)) return null;

    const rules: PlacementRule[] = [];
    for (const raw of doc.rules as unknown[]) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        if (r.document !== 'passport' && r.document !== 'id-card') continue;
        if (typeof r.country !== 'string' || !/^[A-Z]{1,3}$/.test(r.country)) continue;
        if (!Array.isArray(r.positions)) continue;
        const positions = (r.positions as unknown[]).filter(
            (p): p is ChipPosition => typeof p === 'string' && (CHIP_POSITIONS as readonly string[]).includes(p),
        );
        // Every position must be one this build knows: half a rule would send
        // the holder to the wrong place first.
        if (positions.length === 0 || positions.length !== r.positions.length) continue;
        const from = typeof r.issuedFrom === 'string' ? r.issuedFrom : undefined;
        const to = typeof r.issuedTo === 'string' ? r.issuedTo : undefined;
        if ((from && monthIndex(from) === null) || (to && monthIndex(to) === null)) continue;
        rules.push({
            document: r.document,
            country: r.country,
            issuedFrom: from,
            issuedTo: to,
            positions,
            source: typeof r.source === 'string' ? r.source : '',
        });
    }

    const validity: PlacementDoc['validity'] = {};
    if (doc.validity && typeof doc.validity === 'object') {
        for (const [country, v] of Object.entries(doc.validity as Record<string, unknown>)) {
            if (!v || typeof v !== 'object') continue;
            const { adult, child } = v as Record<string, unknown>;
            const years = (n: unknown) => (typeof n === 'number' && n > 0 && n <= 20 ? n : undefined);
            validity[country] = { adult: years(adult), child: years(child) };
        }
    }
    return { schema: PLACEMENT_SCHEMA, issuedAt: doc.issuedAt, validity, rules };
}

/** The list compiled into this build. */
export const BUILT_IN_PLACEMENT: PlacementDoc =
    parsePlacementDoc(builtIn) ?? { schema: PLACEMENT_SCHEMA, issuedAt: '1970-01-01T00:00:00Z', rules: [] };

/** A machine readable date, `YYMMDD`, as year and month. */
function mrzDate(value: string, kind: 'birth' | 'expiry', now: Date): { year: number; month: number } | null {
    const m = /^(\d{2})(\d{2})\d{2}$/.exec(value.trim());
    if (!m) return null;
    const yy = Number(m[1]);
    const month = Number(m[2]);
    if (month < 1 || month > 12) return null;
    // Two digits of year: an expiry is in this century; a birth is in the
    // past, so a year ahead of now belongs to the last one.
    let year = 2000 + yy;
    if (kind === 'birth' && year > now.getFullYear()) year -= 100;
    return { year, month };
}

/**
 * When the document was issued, as a count of months, worked out from what the
 * machine readable zone does say. The issue date is printed on the page but is
 * not in the zone; the expiry is, and a document is valid for a known number of
 * years that depends on whether its holder was a child.
 */
export function estimateIssueMonth(
    doc: PlacementDoc,
    country: string,
    expiry: string,
    birth: string,
    now: Date = new Date(),
): number | null {
    const exp = mrzDate(expiry, 'expiry', now);
    if (!exp) return null;
    const adult = doc.validity?.[country]?.adult ?? 10;
    const child = doc.validity?.[country]?.child ?? 5;
    const born = mrzDate(birth, 'birth', now);
    // Adult if they were sixteen or over when an adult document would have
    // been issued. Without a birth date, assume the commoner case.
    const adultAtIssue = born ? exp.year - adult - born.year >= 16 : true;
    return exp.year * 12 + (exp.month - 1) - (adultAtIssue ? adult : child) * 12;
}

/**
 * Where to lay the phone for this document.
 *
 * The issue date is an estimate, so a rule is taken when its range reaches
 * within a year of it. Where two rules do (a document issued near a change of
 * design), both are given, the likelier first.
 */
export function placementFor(
    doc: PlacementDoc,
    subject: { document: PlacementDocument; country?: string; expiry?: string; birth?: string },
    now: Date = new Date(),
): Placement {
    const fallback: Placement = { positions: ORDER_TO_TRY[subject.document], known: false };
    const country = subject.country?.replace(/</g, '').toUpperCase();
    if (!country) return fallback;

    const rules = doc.rules.filter((r) => r.document === subject.document && r.country === country);
    if (rules.length === 0) return fallback;

    const issued = subject.expiry ? estimateIssueMonth(doc, country, subject.expiry, subject.birth ?? '', now) : null;
    const ranked: { rule: PlacementRule; distance: number }[] = [];
    for (const rule of rules) {
        const from = monthIndex(rule.issuedFrom);
        const to = monthIndex(rule.issuedTo);
        if (from === null && to === null) {
            ranked.push({ rule, distance: 0 });
            continue;
        }
        // A rule bounded in time says nothing about a document of unknown age.
        if (issued === null) continue;
        const distance = from !== null && issued < from ? from - issued : to !== null && issued > to ? issued - to : 0;
        if (distance <= ESTIMATE_SLACK_MONTHS) ranked.push({ rule, distance });
    }
    if (ranked.length === 0) return fallback;

    ranked.sort((a, b) => a.distance - b.distance);
    const positions: ChipPosition[] = [];
    for (const { rule } of ranked) {
        for (const p of rule.positions) if (!positions.includes(p)) positions.push(p);
    }
    // Then the rest of the general order. A rule can be out of date, or the
    // estimate of the issue date out by more than allowed for, and the holder
    // must still be led to the chip: a wrong rule should cost time, not the
    // check.
    for (const p of ORDER_TO_TRY[subject.document]) if (!positions.includes(p)) positions.push(p);
    return { positions, known: true };
}
