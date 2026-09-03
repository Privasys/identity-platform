// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Wrap the version-floor document in a signed envelope for publishing.
 *
 *   WALLET_VERSION_SIGNING_KEY=<pkcs8 pem> \
 *   WALLET_VERSION_KEY_ID=<id> \
 *   node sign.cjs version.json > envelope.json
 *
 * The payload travels base64url-encoded rather than inline, so the bytes signed
 * here are byte-for-byte the bytes the wallet verifies. Nothing has to agree on
 * a canonical JSON form, and no whitespace or key-order difference between two
 * serialisers can invalidate a signature or, worse, let two different documents
 * share one.
 *
 * Ed25519 through Node's own crypto, so CI needs no dependency to publish. The
 * wallet verifies with @noble/curves; both implement RFC 8032 PureEdDSA and the
 * pairing is asserted by wallet/src/__tests__/app-version.test.ts.
 *
 * Signing is what makes this document worth more than the TLS certificate in
 * front of it. Serving privasys.id is enough to REPLACE the document; it is not
 * enough to make a wallet act on it.
 */

const crypto = require('node:crypto');
const { readFileSync } = require('node:fs');

const { validateManifest } = require('./validate.cjs');

function b64u(buf) {
    return Buffer.from(buf).toString('base64url');
}

function main() {
    const path = process.argv[2];
    const pem = process.env.WALLET_VERSION_SIGNING_KEY;
    const keyId = process.env.WALLET_VERSION_KEY_ID;

    if (!path) {
        console.error('usage: node sign.cjs <version.json>');
        process.exit(2);
    }
    if (!pem || !keyId) {
        console.error('WALLET_VERSION_SIGNING_KEY and WALLET_VERSION_KEY_ID must both be set');
        process.exit(2);
    }

    const raw = readFileSync(path, 'utf8');
    let doc;
    try {
        doc = JSON.parse(raw);
    } catch (e) {
        console.error(`${path}: not valid JSON: ${e.message}`);
        process.exit(1);
    }

    // Signed documents are still checked. A signature makes a document
    // authentic, not correct, and this one can wall an installed base.
    const errors = validateManifest(doc);
    if (errors.length > 0) {
        for (const e of errors) console.error(`  ✗ ${e}`);
        process.exit(1);
    }

    // Re-serialise rather than signing the file bytes: it strips whatever
    // trailing newline or CRLF the checkout happens to carry, so the envelope
    // does not change when nothing meaningful did.
    const payload = Buffer.from(JSON.stringify(doc), 'utf8');
    const sig = crypto.sign(null, payload, crypto.createPrivateKey(pem));

    process.stdout.write(
        JSON.stringify({ keyId, payload: b64u(payload), sig: b64u(sig) }) + '\n',
    );
}

main();
