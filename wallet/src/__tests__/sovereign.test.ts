// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Sovereign data root (Phase 2): BIP39 transforms, backup envelope
 * round-trip, W derivation, and the attestation release gate.
 */

// Mock storage
jest.mock('@/utils/storage', () => {
    const store: Record<string, string> = {};
    return {
        getItemAsync: jest.fn(async (key: string) => store[key] ?? null),
        setItemAsync: jest.fn(async (key: string, value: string) => {
            store[key] = value;
        }),
        deleteItemAsync: jest.fn(async (key: string) => {
            delete store[key];
        }),
    };
});

// Mock expo-crypto with real (insecure, test-only) randomness so salts,
// nonces and generated roots are distinct across calls.
jest.mock('expo-crypto', () => ({
    getRandomBytes: jest.fn((n: number) => {
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
        return out;
    }),
    getRandomBytesAsync: jest.fn(async (n: number) => {
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
        return out;
    }),
}));

import {
    mnemonicToEntropy,
    entropyToMnemonic,
    bip39ChecksumValid,
    generateMnemonic,
    normaliseMnemonic,
    phraseHashHex,
} from '@/services/bip39';
import {
    deriveW,
    ensureDataRoot,
    installDataRoot,
    sovereignKeyForAttestedApp,
    unwrapSovereignBackup,
    wrapSovereignBackup,
    __clearRootCacheForTests,
} from '@/services/sovereign';
import { bytesToBase64url } from '@/utils/encoding';

function randomEntropy(): Uint8Array {
    const e = new Uint8Array(32);
    for (let i = 0; i < 32; i++) e[i] = Math.floor(Math.random() * 256);
    return e;
}

describe('bip39', () => {
    it('round-trips entropy -> mnemonic -> entropy', () => {
        for (let round = 0; round < 5; round++) {
            const entropy = randomEntropy();
            const words = entropyToMnemonic(entropy);
            expect(words).toHaveLength(24);
            const back = mnemonicToEntropy(words);
            expect(back).not.toBeNull();
            expect(Array.from(back!)).toEqual(Array.from(entropy));
        }
    });

    it('rejects a swapped word via the checksum', () => {
        const words = entropyToMnemonic(randomEntropy());
        const corrupted = [...words];
        corrupted[3] = corrupted[3] === 'abandon' ? 'ability' : 'abandon';
        expect(bip39ChecksumValid(words)).toBe(true);
        expect(bip39ChecksumValid(corrupted)).toBe(false);
        expect(mnemonicToEntropy(corrupted)).toBeNull();
    });

    it('rejects wrong word counts and non-wordlist words', () => {
        expect(mnemonicToEntropy(['abandon'])).toBeNull();
        const words = entropyToMnemonic(randomEntropy());
        words[0] = 'notaword';
        expect(mnemonicToEntropy(words)).toBeNull();
    });

    it('normalises whitespace and case', () => {
        const words = entropyToMnemonic(randomEntropy());
        const messy = '  ' + words.join('   ').toUpperCase() + ' \n';
        expect(normaliseMnemonic(messy)).toEqual(words);
    });

    it('generates valid client-side phrases', async () => {
        const a = await generateMnemonic();
        const b = await generateMnemonic();
        expect(a).toHaveLength(24);
        expect(bip39ChecksumValid(a)).toBe(true);
        expect(bip39ChecksumValid(b)).toBe(true);
        expect(a.join(' ')).not.toEqual(b.join(' '));
    });

    it('phrase hash matches the IdP HashPhrase vector', () => {
        // Pinned on both sides: the IdP test asserts HashPhrase of this
        // exact phrase equals the same hex (internal/recovery/backup_test.go).
        // If either side drifts, registration and recovery stop matching.
        const words = (
            'abandon ability able about above absent absorb abstract absurd abuse access accident ' +
            'account accuse achieve acid acoustic acquire across act action actor actress actual'
        ).split(' ');
        expect(phraseHashHex(words)).toBe(
            '0b07c3c70386fced9d5953dddd210300099eff25a37c98290c5b4f57aab778d8'
        );
    });
});

describe('backup envelope', () => {
    const phrase = () => entropyToMnemonic(randomEntropy()).join(' ');

    it('round-trips under the right phrase', () => {
        const p = phrase();
        const payload = { dataRootB64: bytesToBase64url(randomEntropy()), pairwiseSeedHex: 'ab'.repeat(32) };
        const blob = wrapSovereignBackup(p, payload);
        const out = unwrapSovereignBackup(p, blob);
        expect(out).toEqual(payload);
    });

    it('carries a null pairwise seed', () => {
        const p = phrase();
        const payload = { dataRootB64: bytesToBase64url(randomEntropy()), pairwiseSeedHex: null };
        expect(unwrapSovereignBackup(p, wrapSovereignBackup(p, payload))).toEqual(payload);
    });

    it('refuses the wrong phrase', () => {
        const blob = wrapSovereignBackup(phrase(), {
            dataRootB64: bytesToBase64url(randomEntropy()),
            pairwiseSeedHex: null,
        });
        expect(unwrapSovereignBackup(phrase(), blob)).toBeNull();
    });

    it('refuses a tampered blob', () => {
        const p = phrase();
        const blob = wrapSovereignBackup(p, {
            dataRootB64: bytesToBase64url(randomEntropy()),
            pairwiseSeedHex: null,
        });
        const tampered = blob.slice(0, -2) + (blob.endsWith('AA') ? 'BB' : 'AA');
        expect(unwrapSovereignBackup(p, tampered)).toBeNull();
    });

    it('refuses to wrap under an invalid phrase', () => {
        expect(() =>
            wrapSovereignBackup('not a valid phrase at all', {
                dataRootB64: bytesToBase64url(randomEntropy()),
                pairwiseSeedHex: null,
            })
        ).toThrow(/BIP39/);
    });
});

describe('W derivation', () => {
    it('is deterministic and separated by sub, app and root', () => {
        const root = randomEntropy();
        const w1 = deriveW(root, 'sub-a', 'aabb');
        expect(w1).toHaveLength(32);
        expect(Array.from(deriveW(root, 'sub-a', 'aabb'))).toEqual(Array.from(w1));
        expect(Array.from(deriveW(root, 'sub-b', 'aabb'))).not.toEqual(Array.from(w1));
        expect(Array.from(deriveW(root, 'sub-a', 'ccdd'))).not.toEqual(Array.from(w1));
        expect(Array.from(deriveW(randomEntropy(), 'sub-a', 'aabb'))).not.toEqual(Array.from(w1));
        // App id casing must not fork the key space.
        expect(Array.from(deriveW(root, 'sub-a', 'AABB'))).toEqual(Array.from(w1));
    });
});

describe('root lifecycle and release gate', () => {
    it('generates once and releases only to verified attestations', async () => {
        __clearRootCacheForTests();
        const r1 = await ensureDataRoot();
        const r2 = await ensureDataRoot();
        expect(bytesToBase64url(r1)).toEqual(bytesToBase64url(r2));

        const w = await sovereignKeyForAttestedApp({ status: 'verified' }, 'sub', 'aabb');
        expect(Array.from(w)).toEqual(Array.from(deriveW(r1, 'sub', 'aabb')));

        await expect(sovereignKeyForAttestedApp({ status: 'unreachable' }, 'sub', 'aabb')).rejects.toThrow(
            /not 'verified'/
        );
        await expect(sovereignKeyForAttestedApp({ status: 'invalid' }, 'sub', 'aabb')).rejects.toThrow();
        await expect(sovereignKeyForAttestedApp({ status: 'verified' }, 'sub', '')).rejects.toThrow(/app id/);
    });

    it('installs a recovered root but refuses to overwrite a different one', async () => {
        const current = await ensureDataRoot();
        await installDataRoot(current); // same root: fine
        await expect(installDataRoot(randomEntropy())).rejects.toThrow(/refusing to overwrite/);
    });
});
