// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The deploy-time guard on the version-floor document.
 *
 * The client is lenient on purpose: on a device the safe reading of a broken
 * document is "no floor". That leniency is exactly why this guard has to be
 * strict, because on the publishing side the same mistakes are invisible. A
 * misspelled platform, a mistyped level, a floor with no explanation: each one
 * publishes cleanly, returns 200, and does nothing, or does the gentler thing
 * when the point was to stop people.
 *
 * The document that ships in the repo is checked here too, so `main` can never
 * hold one the deploy would refuse.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// CommonJS, and required rather than imported, so the very same file CI runs
// is the one under test here. A second copy of these rules would drift.
const { validateManifest } = require('../../../idp/wallet-version/validate.cjs') as {
    validateManifest: (doc: unknown, now?: Date) => string[];
};

const NOW = new Date('2026-08-29T12:00:00Z');

function doc(over: Record<string, unknown> = {}) {
    return {
        schema: 1,
        issuedAt: '2026-08-29T10:00:00Z',
        platforms: { ios: { minimum: '1.3.92', level: 'required' } },
        notice: {
            id: 'passport-fix',
            text: { 'en-GB': { title: 'Update', body: 'Because.' } },
        },
        ...over,
    };
}

describe('validateManifest', () => {
    it('accepts a well-formed floor', () => {
        expect(validateManifest(doc(), NOW)).toEqual([]);
    });

    it('accepts the empty resting state, which needs no notice', () => {
        expect(
            validateManifest(
                { schema: 1, issuedAt: '2026-08-29T10:00:00Z', platforms: {}, notice: { id: 'none', text: {} } },
                NOW,
            ),
        ).toEqual([]);
    });

    it.each([
        ['not an object', 'nope'],
        ['null', null],
        ['an array', []],
    ])('rejects %s', (_label, bad) => {
        expect(validateManifest(bad, NOW).length).toBeGreaterThan(0);
    });

    it('rejects a schema it was not written for', () => {
        expect(validateManifest(doc({ schema: 2 }), NOW).join()).toContain('schema');
    });

    it.each([
        ['missing', undefined],
        ['unparseable', 'next tuesday'],
    ])('rejects an issuedAt that is %s', (_label, issuedAt) => {
        expect(validateManifest(doc({ issuedAt }), NOW).join()).toContain('issuedAt');
    });

    // A future timestamp pins every device to that document: the client ignores
    // anything it reads as older than what it has seen.
    it('rejects an issuedAt in the future', () => {
        expect(validateManifest(doc({ issuedAt: '2027-01-01T00:00:00Z' }), NOW).join()).toContain('future');
    });

    it('allows a few minutes of clock skew', () => {
        expect(validateManifest(doc({ issuedAt: '2026-08-29T12:02:00Z' }), NOW)).toEqual([]);
    });

    // Each of these publishes cleanly and does nothing on device.
    it('rejects a platform no device answers to', () => {
        const errors = validateManifest(doc({ platforms: { iOS: { minimum: '1.3.92' } } }), NOW);
        expect(errors.join()).toContain('unknown platform');
    });

    it.each([
        ['1.3', 'two components'],
        ['v1.3.92', 'a v prefix'],
        ['1.3.92-beta', 'a suffix'],
        [undefined, 'nothing'],
    ])('rejects a minimum of %s (%s)', (minimum, _why) => {
        expect(validateManifest(doc({ platforms: { ios: { minimum } } }), NOW).join()).toContain('X.Y.Z');
    });

    // The one that turns an intended wall into a nag.
    it('rejects a mistyped level', () => {
        expect(
            validateManifest(doc({ platforms: { ios: { minimum: '1.3.92', level: 'requried' } } }), NOW).join(),
        ).toContain('level');
    });

    it('allows level to be omitted, which means recommended', () => {
        expect(validateManifest(doc({ platforms: { ios: { minimum: '1.3.92' } } }), NOW)).toEqual([]);
    });

    it.each([
        ['no notice', { notice: undefined }],
        ['no English text', { notice: { id: 'x', text: { fr: { title: 'a', body: 'b' } } } }],
        ['an empty title', { notice: { id: 'x', text: { 'en-GB': { title: ' ', body: 'b' } } } }],
        ['an empty body', { notice: { id: 'x', text: { 'en-GB': { title: 'a', body: '' } } } }],
    ])('rejects a floor with %s, because the client would ignore it', (_label, over) => {
        expect(validateManifest(doc(over), NOW).join()).toContain('ignores it');
    });

    it('rejects a real floor still carrying the placeholder notice id', () => {
        const errors = validateManifest(
            doc({ notice: { id: 'none', text: { 'en-GB': { title: 'a', body: 'b' } } } }),
            NOW,
        );
        expect(errors.join()).toContain('notice.id');
    });

    it('accepts en as a fallback for en-GB', () => {
        expect(
            validateManifest(doc({ notice: { id: 'x', text: { en: { title: 'a', body: 'b' } } } }), NOW),
        ).toEqual([]);
    });
});

describe('the document committed in this repo', () => {
    it('would pass its own deploy', () => {
        const path = join(__dirname, '../../../idp/wallet-version/version.json');
        const committed = JSON.parse(readFileSync(path, 'utf8'));
        expect(validateManifest(committed)).toEqual([]);
    });
});
