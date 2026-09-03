// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Mint a signing key for the version-floor document.
 *
 *   node gen-key.cjs [keyId]
 *
 * Run it somewhere you would be happy running `ssh-keygen`. It prints two
 * things and keeps neither:
 *
 *   - a PKCS#8 private key, for the WALLET_VERSION_SIGNING_KEY repository
 *     secret. It must never enter this repository.
 *   - a base64url public key, for VERSION_SIGNING_KEYS in
 *     wallet/src/services/version-signing-keys.ts.
 *
 * The public key has to reach devices BEFORE the private one is used to sign
 * anything: only builds carrying it can verify. Ship the release, wait for it
 * to land, then set the secret. Doing it the other way round publishes floors
 * that every wallet ignores, which looks exactly like the feature not working.
 */

const crypto = require('node:crypto');

const keyId = process.argv[2] || `wallet-version-${new Date().toISOString().slice(0, 7)}`;

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
// The JWK `x` for an Ed25519 key IS the 32-byte public key, base64url-encoded,
// which is the form the wallet pins.
const pub = publicKey.export({ format: 'jwk' }).x;

console.log(`keyId: ${keyId}`);
console.log('');
console.log('── Pin this in wallet/src/services/version-signing-keys.ts ──');
console.log(`    '${keyId}': '${pub}',`);
console.log('');
console.log('── Repository secrets ──');
console.log(`WALLET_VERSION_KEY_ID      = ${keyId}`);
console.log('WALLET_VERSION_SIGNING_KEY = (the PEM below, including both header lines)');
console.log('');
console.log(pem.trim());
console.log('');
console.log('Ship the public key in a release and wait for adoption BEFORE setting');
console.log('the secret. A floor signed by a key no build carries is ignored by every');
console.log('wallet, which is indistinguishable from the feature being broken.');
