// Bundled with esbuild and run by `node --test` (npm test): the SDK ships no test
// framework, and these are pure functions that need none.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { CANONICAL_ATTRIBUTES, type CanonicalAttribute } from '../src/attributes';
import {
    attributeSections,
    disclosureCost,
    formatCredits,
    priceOf,
} from '../src/attribute-pricing';

const attr = (over: Partial<CanonicalAttribute> & { key: string }): CanonicalAttribute =>
    ({ label: over.key, scope: 'profile', ...over }) as CanonicalAttribute;

const holder = attr({ key: 'email', assurance: 'self_asserted' });
const govFree = attr({ key: 'sex', scope: 'identity', assurance: 'gov_verified' });
const over18 = attr({
    key: 'age_over_18',
    scope: 'identity',
    assurance: 'gov_verified',
    marketplace: { key: 'privasys:age_over_18', billable: true },
});
const over21 = attr({
    key: 'age_over_21',
    scope: 'identity',
    assurance: 'gov_verified',
    marketplace: { key: 'privasys:age_over_21', billable: true },
});
const prices = new Map([
    ['privasys:age_over_18', 10_000],
    ['privasys:age_over_21', 10_000],
]);

test('credits read as pounds at the platform rate', () => {
    assert.equal(formatCredits(1_000_000), '£1.00');
    assert.equal(formatCredits(10_000), '£0.01');
    // Under a penny still reads as a price rather than £0.00.
    assert.equal(formatCredits(1_234), '£0.0012');
});

test('a price is read by the key the marketplace sells under', () => {
    assert.equal(priceOf(prices, over18), 10_000);
    assert.equal(priceOf(prices, holder), undefined);
    assert.equal(priceOf(null, over18), undefined);
});

test('a disclosure costs the sum of what is sold in it', () => {
    const all = [holder, govFree, over18, over21];
    assert.equal(disclosureCost(prices, all, ['email', 'age_over_18', 'age_over_21']), 20_000);
    assert.equal(disclosureCost(prices, all, ['email', 'sex']), 0);
});

test('a bill that cannot be priced in full is not totalled', () => {
    // Understating what a disclosure costs is the one mistake this must not make.
    const all = [over18, over21];
    assert.equal(disclosureCost(new Map([['privasys:age_over_18', 10_000]]), all, ['age_over_18', 'age_over_21']), undefined);
    assert.equal(disclosureCost(null, all, ['age_over_18']), undefined);
});

test('sections say the assurance once: holder, then government, then paid last', () => {
    const sections = attributeSections([over18, holder, govFree, over21]);
    assert.deepEqual(
        sections.map((s) => [s.id, s.attributes.map((a) => a.key)]),
        [
            ['holder', ['email']],
            ['gov', ['sex']],
            ['paid', ['age_over_18', 'age_over_21']],
        ],
    );
});

test('an empty section is left out', () => {
    assert.deepEqual(
        attributeSections([holder]).map((s) => s.id),
        ['holder'],
    );
});

test('every sold key in the bundled referential lands in the paid section', () => {
    const paid = attributeSections(CANONICAL_ATTRIBUTES).find((s) => s.id === 'paid');
    assert.ok(paid, 'the referential sells something');
    for (const a of paid.attributes) assert.equal(a.marketplace?.billable, true, a.key);
});
