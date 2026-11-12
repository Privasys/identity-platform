// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Wrap the chip-placement list in a signed envelope for publishing.
 *
 *   WALLET_VERSION_SIGNING_KEY=<pkcs8 pem> \
 *   WALLET_VERSION_KEY_ID=<id> \
 *   node sign.cjs ../wallet/src/services/chip-placement.data.json > envelope.json
 *
 * The same envelope, and the same publisher key, as the version floor
 * (idp/wallet-version/sign.cjs): the wallet already pins that key and opens
 * both with one check. The two documents cannot stand in for each other,
 * because each is refused under the other's schema.
 *
 * The payload travels base64url-encoded, so the bytes signed here are the
 * bytes the wallet verifies and no canonical JSON form has to be agreed.
 */

const crypto = require('node:crypto');
const { readFileSync } = require('node:fs');

const { validatePlacement } = require('./validate.cjs');

const b64u = (buf) => Buffer.from(buf).toString('base64url');

function main() {
    const path = process.argv[2];
    const pem = process.env.WALLET_VERSION_SIGNING_KEY;
    const keyId = process.env.WALLET_VERSION_KEY_ID;

    if (!path) {
        console.error('usage: node sign.cjs <chip-placement.data.json>');
        process.exit(2);
    }
    if (!pem || !keyId) {
        console.error('WALLET_VERSION_SIGNING_KEY and WALLET_VERSION_KEY_ID must both be set');
        process.exit(2);
    }

    let doc;
    try {
        doc = JSON.parse(readFileSync(path, 'utf8'));
    } catch (e) {
        console.error(`${path}: not valid JSON: ${e.message}`);
        process.exit(1);
    }

    // A signature makes a list authentic, not correct.
    const errors = validatePlacement(doc);
    if (errors.length > 0) {
        for (const e of errors) console.error(`  ✗ ${e}`);
        process.exit(1);
    }

    // Re-serialised, so a trailing newline or CRLF in the checkout does not
    // change the envelope when nothing meaningful did.
    const payload = Buffer.from(JSON.stringify(doc), 'utf8');
    const sig = crypto.sign(null, payload, crypto.createPrivateKey(pem));
    process.stdout.write(JSON.stringify({ keyId, payload: b64u(payload), sig: b64u(sig) }) + '\n');
}

main();
