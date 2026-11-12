// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The chip-placement list, from the files people write to the list the wallet
 * reads: the checks a contribution has to pass, run here on the very files the
 * build and the deploy run, and on the list in this build.
 */

import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { ed25519 } from '@noble/curves/ed25519.js';

import builtIn from '@/services/chip-placement.data.json';
import { parsePlacementDoc } from '@/services/chip-placement';

const FOLDER = path.resolve(__dirname, '../../../chip-placement');

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { validateCountry, validatePlacement, SCHEMA } = require('../../../chip-placement/validate.cjs') as {
    validateCountry: (file: unknown, code?: string) => string[];
    validatePlacement: (doc: unknown, now?: Date) => string[];
    SCHEMA: string;
};
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { buildContent, sameContent } = require('../../../chip-placement/build.cjs') as {
    buildContent: () => { validity: unknown; rules: unknown[]; suggestions: unknown[] };
    sameContent: (a: unknown, b: unknown) => boolean;
};

const NOW = new Date('2026-11-12T12:00:00Z');
const base = (rules: unknown[]) => ({ schema: SCHEMA, issuedAt: '2026-11-01T00:00:00Z', validity: {}, rules });
const built = (over: Record<string, unknown> = {}) => ({
    document: 'passport', country: 'XXA', positions: ['back-cover'], ...over,
});
const written = (over: Record<string, unknown> = {}) => ({
    country: 'XXA',
    name: 'Example',
    rules: [{
        document: 'passport',
        positions: ['back-cover'],
        evidence: 'documented',
        source: 'https://example.org/where-the-chip-is',
        sourceType: 'government',
        quote: 'The chip is in the back cover of the passport.',
        checked: '2026-11-12',
        ...over,
    }],
});

describe('the country files', () => {
    const files = readdirSync(path.join(FOLDER, 'countries')).filter((f) => f.endsWith('.json'));

    it.each(files)('%s names a page and quotes it for every rule', (f) => {
        const file = JSON.parse(readFileSync(path.join(FOLDER, 'countries', f), 'utf8'));
        expect(validateCountry(file, f.replace(/\.json$/, ''))).toEqual([]);
    });

    it('are ISO throughout, Germany included', () => {
        expect(files).toContain('DEU.json');
        expect(files.every((f) => /^[A-Z]{3}\.json$/.test(f))).toBe(true);
        const states = (builtIn.rules as { country: string }[]).map((r) => r.country);
        expect(states).toContain('DEU');
        expect(states.every((c) => /^[A-Z]{3}$/.test(c))).toBe(true);
    });

    it('build the list in this build, to the rule', () => {
        // A country file changed without `node chip-placement/build.cjs` would
        // ship a list that does not say what the folder says.
        expect(sameContent(builtIn, buildContent())).toBe(true);
    });
});

describe('a country file is refused', () => {
    it.each([
        ['with no source', { source: undefined }],
        ['with a source that is not a page', { source: 'one passport we looked at' }],
        ['with no sentence quoted from it', { quote: '' }],
        ['with no day it was read', { checked: undefined }],
        ['with a made-up kind of evidence', { evidence: 'obvious' }],
        ['with a made-up kind of source', { sourceType: 'forum' }],
        ['with a place the wallet has no words for', { positions: ['spine'] }],
        ['with a year for a month', { issuedFrom: '2020' }],
        ['with a range that ends before it starts', { issuedFrom: '2021-01', issuedTo: '2020-01' }],
        ['with a card position on a passport', { positions: ['card'] }],
    ])('%s', (_name, over) => {
        expect(validateCountry(written(over), 'XXA').length).toBeGreaterThan(0);
    });

    it('when it is named after another country', () => {
        expect(validateCountry(written(), 'XXB').length).toBeGreaterThan(0);
    });

    it('when its country is not an ISO three-letter code', () => {
        expect(validateCountry({ ...written(), country: 'D' }, 'D').length).toBeGreaterThan(0);
    });


    it('but not when it is right', () => {
        expect(validateCountry(written(), 'XXA')).toEqual([]);
        expect(validateCountry(written({ evidence: 'inferred', sourceType: 'printer' }), 'XXA')).toEqual([]);
    });
});

describe('the list in this build', () => {
    it('is publishable as it stands', () => {
        // Against the clock, as the deploy checks it: the list is re-dated
        // whenever it changes, so a fixed date here would go stale.
        expect(validatePlacement(builtIn)).toEqual([]);
    });

    it('loses no rule when the wallet reads it', () => {
        // The wallet drops what it cannot read; the build must have refused it first.
        expect(parsePlacementDoc(builtIn)?.rules.length).toBe(builtIn.rules.length);
    });

    it('carries the bare rule and none of the evidence', () => {
        for (const rule of builtIn.rules as Record<string, unknown>[]) {
            expect(Object.keys(rule).filter((k) => !['document', 'country', 'issuedFrom', 'issuedTo', 'positions'].includes(k))).toEqual([]);
        }
    });
});

describe('a built list is refused', () => {
    it.each([
        ['with a place the wallet has no words for', built({ positions: ['spine'] })],
        ['with no place at all', built({ positions: [] })],
        ['with a full country name', built({ country: 'France' })],
        ['with a year for a month', built({ issuedFrom: '2020' })],
    ])('%s', (_name, r) => {
        expect(validatePlacement(base([r]), NOW).length).toBeGreaterThan(0);
    });

    it('when it is dated ahead, since no later list could replace it', () => {
        expect(validatePlacement({ ...base([]), issuedAt: '2027-01-01T00:00:00Z' }, NOW).length).toBeGreaterThan(0);
    });

    it('under another schema', () => {
        expect(validatePlacement({ ...base([]), schema: 1 }, NOW).length).toBeGreaterThan(0);
    });
});

describe('a good list', () => {
    it('passes', () => {
        expect(validatePlacement(base([built(), built({ document: 'id-card', positions: ['card'] })]), NOW)).toEqual([]);
    });

    it('signed by the deploy opens with the check the wallet uses', () => {
        // The pairing the whole feature rests on: Node signs, @noble verifies.
        const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
        const out = execFileSync(
            process.execPath,
            [path.join(FOLDER, 'sign.cjs'), path.resolve(__dirname, '../services/chip-placement.data.json')],
            {
                env: {
                    ...process.env,
                    WALLET_VERSION_SIGNING_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
                    WALLET_VERSION_KEY_ID: 'test-key',
                },
            },
        );
        const env = JSON.parse(out.toString('utf8')) as { keyId: string; payload: string; sig: string };
        const pub = Buffer.from((publicKey.export({ format: 'jwk' }) as { x: string }).x, 'base64url');
        const payload = Buffer.from(env.payload, 'base64url');
        expect(env.keyId).toBe('test-key');
        expect(ed25519.verify(Buffer.from(env.sig, 'base64url'), payload, pub)).toBe(true);
        expect(parsePlacementDoc(JSON.parse(payload.toString('utf8')))).not.toBeNull();
    });
});
