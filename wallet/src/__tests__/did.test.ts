// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Smoke tests for DID services — base58btc encoding, key compression,
 * pairwise sub derivation, and canonical DID generation.
 *
 * Native modules (NativeKeys, expo-crypto) are mocked since these tests
 * run in Node, not on a device.
 */

// --- Mocks ---

// Mock NativeKeys — return a known uncompressed P-256 public key
jest.mock('../../modules/native-keys/src/index', () => ({
    getPublicKey: jest.fn().mockResolvedValue({
        publicKey:
            // 65-byte uncompressed P-256 key (base64url): 04 || x(32) || y(32)
            'BAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
        keyId: 'privasys-wallet-default',
        hardwareBacked: false,
    }),
}));

// Mock expo-crypto
jest.mock('expo-crypto', () => ({
    getRandomBytesAsync: jest.fn().mockResolvedValue(
        new Uint8Array(32).fill(0xab)
    ),
    randomUUID: jest.fn().mockReturnValue('test-uuid-1234'),
    digestStringAsync: jest.fn().mockImplementation(
        async (_algo: string, input: string) => {
            // FNV-1a inspired deterministic hash — produces different outputs for different inputs
            let h = 0x811c9dc5;
            for (let i = 0; i < input.length; i++) {
                h ^= input.charCodeAt(i);
                h = Math.imul(h, 0x01000193);
            }
            const u = h >>> 0;
            const hex = u.toString(16).padStart(8, '0');
            return hex.repeat(8);
        }
    ),
    CryptoDigestAlgorithm: { SHA256: 'SHA-256' },
}));

import {
    generateDid,
    generatePairwiseSeed,
    deriveAppSub,
    generateCanonicalDid,
    resolveDidDocument,
} from '@/services/did';

describe('did.ts', () => {
    describe('generateDid', () => {
        it('produces a did:key string starting with did:key:z', async () => {
            const did = await generateDid();
            expect(did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
        });

        it('is deterministic for the same key', async () => {
            const a = await generateDid();
            const b = await generateDid();
            expect(a).toBe(b);
        });
    });

    describe('resolveDidDocument', () => {
        it('returns a valid DID document shape', () => {
            const doc = resolveDidDocument('did:key:zTestKey123');
            expect(doc.id).toBe('did:key:zTestKey123');
            expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1');
            expect(doc.verificationMethod).toHaveLength(1);
            expect(doc.authentication).toHaveLength(1);
            expect(doc.assertionMethod).toHaveLength(1);
        });
    });

    describe('generatePairwiseSeed', () => {
        it('returns a 64-char hex string (32 bytes)', async () => {
            const seed = await generatePairwiseSeed();
            expect(seed).toMatch(/^[0-9a-f]{64}$/);
        });
    });

    describe('deriveAppSub', () => {
        const seed = 'ab'.repeat(32); // 64-char hex seed

        it('returns a hex string', async () => {
            const sub = await deriveAppSub(seed, 'app1.privasys.org');
            expect(sub).toMatch(/^[0-9a-f]+$/);
        });

        it('is deterministic — same seed + rpId produces same sub', async () => {
            const a = await deriveAppSub(seed, 'app1.privasys.org');
            const b = await deriveAppSub(seed, 'app1.privasys.org');
            expect(a).toBe(b);
        });

        it('produces different subs for different rpIds', async () => {
            const sub1 = await deriveAppSub(seed, 'app1.privasys.org');
            const sub2 = await deriveAppSub(seed, 'app2.privasys.org');
            expect(sub1).not.toBe(sub2);
        });

        it('produces different subs for different seeds', async () => {
            const seed2 = 'cd'.repeat(32);
            const sub1 = await deriveAppSub(seed, 'app1.privasys.org');
            const sub2 = await deriveAppSub(seed2, 'app1.privasys.org');
            expect(sub1).not.toBe(sub2);
        });
    });

    describe('generateCanonicalDid', () => {
        it('returns a did:web:privasys.id:users:... string', async () => {
            const seed = 'ab'.repeat(32);
            const did = await generateCanonicalDid(seed);
            expect(did).toMatch(/^did:web:privasys\.id:users:[0-9a-f]{32}$/);
        });

        it('is deterministic for the same seed', async () => {
            const seed = 'ab'.repeat(32);
            const a = await generateCanonicalDid(seed);
            const b = await generateCanonicalDid(seed);
            expect(a).toBe(b);
        });

        it('produces different DIDs for different seeds', async () => {
            const a = await generateCanonicalDid('ab'.repeat(32));
            const b = await generateCanonicalDid('cd'.repeat(32));
            expect(a).not.toBe(b);
        });
    });
});
