// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The check a chip-placement list passes before it is signed and served, run
 * here on the very file the deploy runs, and on the list in this build.
 */

import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

import { ed25519 } from '@noble/curves/ed25519.js';

import builtIn from '@/services/chip-placement.data.json';
import { parsePlacementDoc } from '@/services/chip-placement';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { validatePlacement, SCHEMA } = require('../../../idp/chip-placement/validate.cjs') as {
    validatePlacement: (doc: unknown, now?: Date) => string[];
    SCHEMA: string;
};

const NOW = new Date('2026-11-12T12:00:00Z');
const base = (rules: unknown[]) => ({ schema: SCHEMA, issuedAt: '2026-11-01T00:00:00Z', validity: {}, rules });
const rule = (over: Record<string, unknown> = {}) => ({
    document: 'passport', country: 'XXA', positions: ['back-cover'], source: 'https://example.org/where', ...over,
});

describe('the list in this build', () => {
    it('is publishable as it stands', () => {
        expect(validatePlacement(builtIn, NOW)).toEqual([]);
    });

    it('loses no rule when the wallet reads it', () => {
        // The wallet drops what it cannot read; the deploy must have refused it first.
        expect(parsePlacementDoc(builtIn)?.rules.length).toBe(builtIn.rules.length);
    });
});

describe('a list is refused', () => {
    it.each([
        ['with no source for a rule', rule({ source: undefined })],
        ['with a source that is not a page', rule({ source: 'one passport we looked at' })],
        ['with a place the wallet has no words for', rule({ positions: ['spine'] })],
        ['with no place at all', rule({ positions: [] })],
        ['with a full country name', rule({ country: 'France' })],
        ['with a year for a month', rule({ issuedFrom: '2020' })],
        ['with a range that ends before it starts', rule({ issuedFrom: '2021-01', issuedTo: '2020-01' })],
        ['with a card position on a passport', rule({ positions: ['card'] })],
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
        expect(validatePlacement(base([rule(), rule({ document: 'id-card', positions: ['card'] })]), NOW)).toEqual([]);
    });

    it('signed by the deploy opens with the check the wallet uses', () => {
        // The pairing the whole feature rests on: Node signs, @noble verifies.
        const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
        const out = execFileSync(
            process.execPath,
            [path.resolve(__dirname, '../../../idp/chip-placement/sign.cjs'), path.resolve(__dirname, '../services/chip-placement.data.json')],
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
