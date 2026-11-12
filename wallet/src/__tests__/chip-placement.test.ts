// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Where the wallet tells a holder to lay their phone.
 *
 * The countries here are made up (XXA, XXB), so no test asserts a fact about a
 * real document that the list itself would need a source for.
 */

import {
    BUILT_IN_PLACEMENT,
    PLACEMENT_SCHEMA,
    estimateIssueMonth,
    parsePlacementDoc,
    placementFor,
    type PlacementDoc,
} from '@/services/chip-placement';

const NOW = new Date('2026-11-12T00:00:00Z');

const doc = (rules: unknown[], validity?: unknown): PlacementDoc => {
    const parsed = parsePlacementDoc({ schema: PLACEMENT_SCHEMA, issuedAt: '2026-11-01T00:00:00Z', rules, validity });
    if (!parsed) throw new Error('fixture did not parse');
    return parsed;
};

const month = (y: number, m: number) => y * 12 + (m - 1);

describe('a document with no rule', () => {
    it('gets the order to try, and says it is not known', () => {
        const p = placementFor(doc([]), { document: 'passport', country: 'XXA', expiry: '300101', birth: '800101' }, NOW);
        expect(p).toEqual({ positions: ['back-cover', 'photo-page', 'front-cover'], known: false });
    });

    it('is a card when it is a card', () => {
        expect(placementFor(doc([]), { document: 'id-card' }, NOW).positions).toEqual(['card']);
    });

    it('is not helped by another document of the same state', () => {
        const d = doc([{ document: 'id-card', country: 'XXA', positions: ['card'], source: 's' }]);
        expect(placementFor(d, { document: 'passport', country: 'XXA', expiry: '300101' }, NOW).known).toBe(false);
    });
});

describe('the issue date', () => {
    it('is ten years before the expiry for an adult', () => {
        expect(estimateIssueMonth(doc([]), 'XXA', '280411', '850828', NOW)).toBe(month(2018, 4));
    });

    it('is five years before the expiry for a child', () => {
        // Born 2015, expires 2029: an adult document would date from age four.
        expect(estimateIssueMonth(doc([]), 'XXA', '290601', '150301', NOW)).toBe(month(2024, 6));
    });

    it('follows the validity a state is known to use', () => {
        const d = doc([], { XXA: { adult: 5, child: 5 } });
        expect(estimateIssueMonth(d, 'XXA', '280411', '850828', NOW)).toBe(month(2023, 4));
    });

    it('places a birth year in the last century when it would otherwise be ahead', () => {
        // "85" is 1985, not 2085.
        expect(estimateIssueMonth(doc([]), 'XXA', '300101', '850101', NOW)).toBe(month(2020, 1));
    });
});

describe('a rule', () => {
    const changed = doc([
        { document: 'passport', country: 'XXA', issuedTo: '2020-02', positions: ['back-cover'], source: 's1' },
        { document: 'passport', country: 'XXA', issuedFrom: '2020-03', positions: ['photo-page'], source: 's2' },
    ]);

    it('applies to a document issued well inside its range', () => {
        // Expires 2034, so issued 2024.
        const p = placementFor(changed, { document: 'passport', country: 'XXA', expiry: '340601', birth: '800101' }, NOW);
        // What the rule says first, then everywhere else a chip can be.
        expect(p).toEqual({ positions: ['photo-page', 'back-cover', 'front-cover'], known: true });
    });

    it('gives both places near a change of design, the likelier first', () => {
        // Expires August 2030, so issued about August 2020: five months after the change.
        const p = placementFor(changed, { document: 'passport', country: 'XXA', expiry: '300801', birth: '800101' }, NOW);
        expect(p.positions.slice(0, 2)).toEqual(['photo-page', 'back-cover']);
    });

    it('with no dates applies whatever the age', () => {
        const d = doc([{ document: 'passport', country: 'XXB', positions: ['front-cover'], source: 's' }]);
        expect(placementFor(d, { document: 'passport', country: 'XXB' }, NOW)).toEqual({
            positions: ['front-cover', 'back-cover', 'photo-page'],
            known: true,
        });
    });

    it('with dates says nothing about a document of unknown age', () => {
        expect(placementFor(changed, { document: 'passport', country: 'XXA' }, NOW).known).toBe(false);
    });

    it('is found for a state written with filler', () => {
        const d = doc([{ document: 'passport', country: 'D', positions: ['front-cover'], source: 's' }]);
        expect(placementFor(d, { document: 'passport', country: 'D<<' }, NOW).known).toBe(true);
    });
});

describe('a list from outside', () => {
    it('is refused whole under another schema', () => {
        // The version floor is signed by the same key: it must not pass as this.
        expect(parsePlacementDoc({ schema: 1, issuedAt: '2026-11-01T00:00:00Z', rules: [] })).toBeNull();
    });

    it('drops a rule that names a place this build has no words for', () => {
        const d = doc([
            { document: 'passport', country: 'XXA', positions: ['back-cover', 'somewhere-new'], source: 's' },
            { document: 'passport', country: 'XXB', positions: ['back-cover'], source: 's' },
        ]);
        expect(d.rules.map((r) => r.country)).toEqual(['XXB']);
    });

    it('drops a rule with a malformed month', () => {
        expect(doc([{ document: 'passport', country: 'XXA', issuedFrom: '2020', positions: ['back-cover'] }]).rules).toEqual([]);
    });
});

describe('the list in the build', () => {
    it('parses, and every rule names where it comes from', () => {
        expect(BUILT_IN_PLACEMENT.schema).toBe(PLACEMENT_SCHEMA);
        for (const rule of BUILT_IN_PLACEMENT.rules) {
            expect(rule.source).toMatch(/^https:\/\//);
            expect(rule.positions.length).toBeGreaterThan(0);
        }
    });
});
