// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * BIP39 mnemonic <-> entropy transforms for 24-word (256-bit) phrases.
 *
 * Lifted out of routes/recover-account.tsx (which previously carried the
 * checksum validator as a private function) because the sovereign backup
 * envelope keys on the phrase's ENTROPY: the recovery phrase is the only
 * user-held secret that survives device loss, so the wallet's root
 * secrets are wrapped under HKDF(entropy) and stored server-side (see
 * services/sovereign.ts). Deriving from the decoded entropy rather than
 * the raw string makes the KEK invariant to whitespace/case differences
 * the normaliser already forgives.
 *
 * Only the 24-word form is supported — the IdP generates 256-bit phrases
 * exclusively (idp internal/recovery/email.go).
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { BIP39_WORDLIST } from '@/services/bip39-wordlist';

/**
 * Normalise a phrase string to its word list: lowercase, trimmed, split on
 * any whitespace run. Matches the IdP's NormalizePhrase, so the entropy
 * derived here is invariant to the formatting differences the server
 * already forgives.
 */
export function normaliseMnemonic(phrase: string): string[] {
    return phrase.trim().toLowerCase().split(/\s+/).filter(Boolean);
}

/**
 * Decode a 24-word phrase to its 32-byte entropy, verifying the BIP39
 * checksum: the final 8 bits of the 264-bit word-index string must equal
 * the first byte of SHA-256 over the 256-bit entropy. A mistyped word
 * that is still in the wordlist slips past a dictionary check but fails
 * this with 255/256 probability. Returns null on any invalid phrase.
 */
export function mnemonicToEntropy(words: string[]): Uint8Array | null {
    if (words.length !== 24) return null;
    const indices = words.map((w) => BIP39_WORDLIST.indexOf(w));
    if (indices.some((i) => i < 0)) return null;
    let bits = '';
    for (const i of indices) bits += i.toString(2).padStart(11, '0');
    const entropy = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        entropy[i] = parseInt(bits.slice(i * 8, (i + 1) * 8), 2);
    }
    const expected = sha256(entropy)[0].toString(2).padStart(8, '0');
    if (bits.slice(256) !== expected) return null;
    return entropy;
}

/** Whether a 24-word phrase decodes with a valid BIP39 checksum. */
export function bip39ChecksumValid(words: string[]): boolean {
    return mnemonicToEntropy(words) !== null;
}

/**
 * Encode 32 bytes of entropy as a 24-word BIP39 phrase (the inverse of
 * mnemonicToEntropy). Not used for phrase GENERATION today — the IdP
 * mints phrases server-side — but it closes the round trip for tests and
 * is the building block if generation ever moves client-side.
 */
export function entropyToMnemonic(entropy: Uint8Array): string[] {
    if (entropy.length !== 32) {
        throw new Error('bip39: entropy must be 32 bytes');
    }
    let bits = '';
    for (const b of entropy) bits += b.toString(2).padStart(8, '0');
    bits += sha256(entropy)[0].toString(2).padStart(8, '0');
    const words: string[] = [];
    for (let i = 0; i < 24; i++) {
        words.push(BIP39_WORDLIST[parseInt(bits.slice(i * 11, (i + 1) * 11), 2)]);
    }
    return words;
}
