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
 * The list is built from the repository's `chip-placement/` folder, where each
 * rule sits with its source and the sentence it rests on; what is compiled in
 * here (chip-placement.data.json) is the bare rule. A newer signed copy can be
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

/**
 * The places the wallet has words and a drawing for.
 *
 * `chip-page` is a stiff page of its own inside the booklet. The two `inside-`
 * places are a cover that is shielded, so the booklet has to be opened and the
 * phone laid on the inside of it. They are places and not a flag on a rule on
 * purpose: a wallet that does not know a place drops the rule and gives the
 * general order, whereas a flag it did not know would be ignored and the
 * holder told to scan a closed cover that blocks the signal.
 */
export const CHIP_POSITIONS = [
    'back-cover', 'front-cover', 'photo-page', 'chip-page', 'inside-back-cover', 'inside-front-cover', 'card',
] as const;
export type ChipPosition = (typeof CHIP_POSITIONS)[number];

export interface PlacementRule {
    document: PlacementDocument;
    /** Issuing state, ISO 3166-1 alpha-3. */
    country: string;
    /** First and last month of issue this holds for, `YYYY-MM`. Open when absent. */
    issuedFrom?: string;
    issuedTo?: string;
    /** Where to try, in order. */
    positions: ChipPosition[];
}

/**
 * How long a state's documents were valid, for documents issued in some span
 * of time. States change this (a ten-year passport becomes a five-year one and
 * back), and they differ on the age from which a holder gets the adult one, so
 * each is given with the months of issue it held for. What is left out is the
 * usual: ten years, five for a child, adult from sixteen.
 */
export interface ValidityPeriod {
    /** First and last month of issue this held for, `YYYY-MM`. Open when absent. */
    issuedFrom?: string;
    issuedTo?: string;
    /** Years an adult's document is valid. */
    adult?: number;
    /** Years a child's document is valid. */
    child?: number;
    /** The age from which a holder is issued the adult one. */
    adultAge?: number;
}

/** What holds where a state says nothing else. */
export const USUAL_VALIDITY = { adult: 10, child: 5, adultAge: 16 } as const;

export interface PlacementDoc {
    schema: string;
    /** ISO time. A copy is only taken over a newer one. */
    issuedAt: string;
    /** How long a state's documents are valid, where or when it is not the usual. */
    validity?: Record<string, ValidityPeriod[]>;
    /** What a source states. */
    rules: PlacementRule[];
    /** What is deduced from something a source states, such as a polycarbonate data page. */
    suggestions?: PlacementRule[];
}

/**
 * How far the first place can be relied on, which decides how it is worded.
 *
 * `documented`: a source states it for a document of this age. Said as a fact.
 * `suggested`:  the best lead there is, and no more: a rule for a neighbouring
 *               design of the same state, or a position deduced and not stated.
 *               Said as "try this first".
 * `none`:       nothing is known of this state's documents. The general order.
 */
export type PlacementConfidence = 'documented' | 'suggested' | 'none';

export interface Placement {
    /** Where to try, in order: the lead first, then everywhere else. Never empty. */
    positions: ChipPosition[];
    confidence: PlacementConfidence;
}

/**
 * What a document writes for its issuing state, where that is not the ISO
 * 3166-1 alpha-3 code the list is keyed on. German documents write `D`.
 */
const WRITTEN_AS: Readonly<Record<string, string>> = { D: 'DEU' };

/** The issuing state read off a document, as its ISO 3166-1 alpha-3 code. */
export function isoCountry(written: string | undefined): string {
    const code = (written ?? '').replace(/</g, '').toUpperCase();
    return WRITTEN_AS[code] ?? code;
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

    const validity: NonNullable<PlacementDoc['validity']> = {};
    if (doc.validity && typeof doc.validity === 'object') {
        const within = (n: unknown, max: number) => (typeof n === 'number' && n > 0 && n <= max ? n : undefined);
        for (const [country, v] of Object.entries(doc.validity as Record<string, unknown>)) {
            // One period, as lists before 1.4.46 wrote it, or several.
            const periods: ValidityPeriod[] = [];
            for (const raw of Array.isArray(v) ? v : [v]) {
                if (!raw || typeof raw !== 'object') continue;
                const p = raw as Record<string, unknown>;
                const from = typeof p.issuedFrom === 'string' ? p.issuedFrom : undefined;
                const to = typeof p.issuedTo === 'string' ? p.issuedTo : undefined;
                if ((from && monthIndex(from) === null) || (to && monthIndex(to) === null)) continue;
                periods.push({
                    issuedFrom: from,
                    issuedTo: to,
                    adult: within(p.adult, 20),
                    child: within(p.child, 20),
                    adultAge: within(p.adultAge, 30),
                });
            }
            if (periods.length > 0) validity[country] = periods;
        }
    }
    return {
        schema: PLACEMENT_SCHEMA,
        issuedAt: doc.issuedAt,
        validity,
        rules: parseRules(doc.rules),
        suggestions: Array.isArray(doc.suggestions) ? parseRules(doc.suggestions) : [],
    };
}

/** The rules of a list that this build can read; the others are dropped. */
function parseRules(list: unknown[]): PlacementRule[] {
    const rules: PlacementRule[] = [];
    for (const raw of list) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        if (r.document !== 'passport' && r.document !== 'id-card') continue;
        if (typeof r.country !== 'string' || !/^[A-Z]{3}$/.test(r.country)) continue;
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
        });
    }
    return rules;
}

/** The list compiled into this build. */
export const BUILT_IN_PLACEMENT: PlacementDoc =
    parsePlacementDoc(builtIn) ?? { schema: PLACEMENT_SCHEMA, issuedAt: '1970-01-01T00:00:00Z', rules: [] };

/** A machine readable date, `YYMMDD`, as a count of months. */
function mrzMonth(value: string, kind: 'birth' | 'expiry', now: Date): number | null {
    const m = /^(\d{2})(\d{2})\d{2}$/.exec(value.trim());
    if (!m) return null;
    const yy = Number(m[1]);
    const month = Number(m[2]);
    if (month < 1 || month > 12) return null;
    // Two digits of year: an expiry is in this century; a birth is in the
    // past, so a year ahead of now belongs to the last one.
    let year = 2000 + yy;
    if (kind === 'birth' && year > now.getFullYear()) year -= 100;
    return year * 12 + (month - 1);
}

/**
 * When the document was issued under one set of validity periods: the adult
 * one if the holder had reached the adult age when it would have begun, the
 * child one otherwise. Without a birth date, the commoner case.
 */
function issuedUnder(period: ValidityPeriod, expiry: number, born: number | null): number {
    const adult = period.adult ?? USUAL_VALIDITY.adult;
    const child = period.child ?? USUAL_VALIDITY.child;
    const adultAge = period.adultAge ?? USUAL_VALIDITY.adultAge;
    const asAdult = expiry - adult * 12;
    const wasAdult = born === null ? true : asAdult - born >= adultAge * 12;
    return wasAdult ? asAdult : expiry - child * 12;
}

/**
 * When the document was issued, as a count of months, worked out from what the
 * machine readable zone does say. The issue date is printed on the page but is
 * not in the zone; the expiry is, and a document is valid for a known number of
 * years that depends on whether its holder was a child.
 *
 * Where a state changed its periods over time, the one that applies is itself
 * dated by issue, which is the unknown. So each is tried, the most recent
 * first, and the one kept is the one whose answer falls inside its own dates.
 */
export function estimateIssueMonth(
    doc: PlacementDoc,
    country: string,
    expiry: string,
    birth: string,
    now: Date = new Date(),
): number | null {
    const exp = mrzMonth(expiry, 'expiry', now);
    if (exp === null) return null;
    const born = mrzMonth(birth, 'birth', now);
    const periods = [...(doc.validity?.[country] ?? [])].sort(
        (a, b) => (monthIndex(b.issuedFrom) ?? -Infinity) - (monthIndex(a.issuedFrom) ?? -Infinity),
    );
    for (const period of periods) {
        const issued = issuedUnder(period, exp, born);
        const from = monthIndex(period.issuedFrom);
        const to = monthIndex(period.issuedTo);
        if ((from === null || issued >= from) && (to === null || issued <= to)) return issued;
    }
    return issuedUnder({}, exp, born);
}

/** A rule of the document's state, with how far its dates are from the document. */
interface Candidate {
    rule: PlacementRule;
    /** Months between the estimated issue date and the rule's range. 0 inside it. */
    distance: number;
    /** Deduced and not stated. */
    inferred: boolean;
    /** The rule's first month, to tell the more recent of two. */
    from: number;
}

/**
 * Where to lay the phone for this document.
 *
 * A rule whose dates hold the document's estimated issue date is what a source
 * states for it: `documented`. The estimate can be out by some months, so the
 * rules that reach within a year of it follow, for a document issued near a
 * change of design.
 *
 * When no rule's dates hold it, the state's rules are still the best lead: its
 * designs follow one another, and the next usually keeps the chip where the
 * last had it. The nearest rule in time is used, which for a document newer
 * than every rule is the most recent one. So is a position that is only
 * deduced. But none of that is what a source states for this document, so it
 * is `suggested`, and worded as somewhere to try first.
 *
 * Whatever leads, the rest of the general order follows it. A lead that is
 * wrong should cost the holder a moment, not the check.
 */
export function placementFor(
    doc: PlacementDoc,
    subject: { document: PlacementDocument; country?: string; expiry?: string; birth?: string },
    now: Date = new Date(),
): Placement {
    const general = ORDER_TO_TRY[subject.document];
    const country = isoCountry(subject.country);
    const ofState = (list: PlacementRule[] | undefined) =>
        (list ?? []).filter((r) => r.document === subject.document && r.country === country);
    const stated = country ? ofState(doc.rules) : [];
    const deduced = country ? ofState(doc.suggestions) : [];
    if (stated.length === 0 && deduced.length === 0) return { positions: general, confidence: 'none' };

    const issued = subject.expiry ? estimateIssueMonth(doc, country, subject.expiry, subject.birth ?? '', now) : null;
    const candidate = (rule: PlacementRule, inferred: boolean): Candidate => {
        const from = monthIndex(rule.issuedFrom);
        const to = monthIndex(rule.issuedTo);
        let distance = 0;
        if (from !== null || to !== null) {
            // A rule bounded in time is not known to hold for a document of unknown age.
            if (issued === null) distance = Number.POSITIVE_INFINITY;
            else if (from !== null && issued < from) distance = from - issued;
            else if (to !== null && issued > to) distance = issued - to;
        }
        return { rule, distance, inferred, from: from ?? Number.NEGATIVE_INFINITY };
    };
    const all = [...stated.map((r) => candidate(r, false)), ...deduced.map((r) => candidate(r, true))];
    // Nearest in time first; of two as near, what is stated, then the more recent.
    all.sort((a, b) =>
        (a.distance === b.distance ? 0 : a.distance - b.distance) || Number(a.inferred) - Number(b.inferred) || b.from - a.from);

    const holds = all.some((c) => !c.inferred && c.distance === 0);
    let leads = all.filter((c) => c.distance <= ESTIMATE_SLACK_MONTHS);
    // No rule reaches the document: take the nearest, or the most recent when
    // the document's age is not known.
    if (leads.length === 0) {
        leads = [Number.isFinite(all[0].distance) ? all[0] : [...all].sort((a, b) => b.from - a.from)[0]];
    }

    const positions: ChipPosition[] = [];
    for (const { rule } of leads) {
        for (const p of rule.positions) if (!positions.includes(p)) positions.push(p);
    }
    for (const p of general) if (!positions.includes(p)) positions.push(p);
    return { positions, confidence: holds ? 'documented' : 'suggested' };
}
