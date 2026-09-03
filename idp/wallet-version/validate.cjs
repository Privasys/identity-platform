// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Check a version-floor document before it goes live.
 *
 * CommonJS on purpose: this is the one piece of the feature that runs BOTH in
 * CI and inside the wallet's jest suite, and CJS is the only module form both
 * load without a build step. A validator nobody can run is a validator nobody
 * can trust, which is the whole reason it is a file rather than YAML.
 *
 * This runs in the deploy workflow and is the last thing between a typo and a
 * walled installed base, so it is a committed, tested module rather than a
 * script inlined in YAML: a guard nobody can run is a guard nobody can trust.
 *
 * It deliberately rejects things the CLIENT tolerates. The client is lenient by
 * design, because on a device the safe failure is "no floor" — but that means a
 * mistake here does not break loudly, it silently disarms the gate or turns a
 * wall into a nag. Catching it at deploy time is the only place it is visible.
 *
 *   node validate.cjs version.json
 */

/** Problems found, in the order they were found. Empty means publishable. */
function validateManifest(doc, now = new Date()) {
    const errors = [];
    const fail = (m) => errors.push(m);

    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
        return ['not a JSON object'];
    }
    if (doc.schema !== 1) fail(`schema must be 1, got ${JSON.stringify(doc.schema)}`);

    const issued = Date.parse(String(doc.issuedAt ?? ''));
    if (!Number.isFinite(issued)) {
        fail(`issuedAt must be an ISO-8601 instant, got ${JSON.stringify(doc.issuedAt)}`);
    } else if (issued > now.getTime() + 5 * 60_000) {
        // A future timestamp pins every device to THIS document for good: the
        // client ignores anything it considers older than what it has already
        // seen, so a clock-skewed push cannot be superseded until real time
        // catches up.
        fail(`issuedAt is in the future: ${doc.issuedAt}`);
    }

    const platforms = doc.platforms ?? {};
    if (typeof platforms !== 'object' || Array.isArray(platforms)) {
        fail('platforms must be an object');
        return errors;
    }
    for (const name of Object.keys(platforms)) {
        // A misspelled platform matches no device, so the floor would simply
        // never apply and the push would look like it worked.
        if (name !== 'ios' && name !== 'android') fail(`unknown platform ${JSON.stringify(name)}`);
        const entry = platforms[name] ?? {};
        if (!/^\d+\.\d+\.\d+$/.test(String(entry.minimum ?? ''))) {
            fail(`${name}: minimum must be X.Y.Z, got ${JSON.stringify(entry.minimum)}`);
        }
        const level = entry.level ?? 'recommended';
        // The client reads anything unrecognised as `recommended`, so a typo
        // here turns an intended wall into a dismissible nag. That is the
        // failure this line exists to catch.
        if (level !== 'recommended' && level !== 'required') {
            fail(`${name}: level must be recommended or required, got ${JSON.stringify(level)}`);
        }
    }

    // A floor with no text the client can resolve is IGNORED on device. Fail
    // here instead, so a push meant to stop people goes out able to say why.
    if (Object.keys(platforms).length > 0) {
        const text = doc.notice?.text ?? {};
        const en = text['en-GB'] ?? text.en;
        if (!en?.title?.trim() || !en?.body?.trim()) {
            fail('a floor needs an en-GB (or en) title and body, or the client ignores it');
        }
        if (!doc.notice?.id || doc.notice.id === 'none') {
            // Dismissals are recorded per id. Shipping a real notice under the
            // placeholder id means anyone who dismissed the last one under it
            // never sees this one.
            fail('a floor needs its own notice.id, not the placeholder');
        }
    }

    return errors;
}

module.exports = { validateManifest };

// Run directly: node validate.cjs <file>
if (require.main === module) {
    const { readFileSync } = require('node:fs');
    const path = process.argv[2];
    if (!path) {
        console.error('usage: node validate.cjs <version.json>');
        process.exit(2);
    }
    let doc;
    try {
        doc = JSON.parse(readFileSync(path, 'utf8'));
    } catch (e) {
        console.error(`${path}: not valid JSON: ${e.message}`);
        process.exit(1);
    }
    const errors = validateManifest(doc);
    if (errors.length > 0) {
        for (const e of errors) console.error(`  ✗ ${e}`);
        process.exit(1);
    }
    console.log(`${path}: ok (${JSON.stringify(doc.platforms ?? {})})`);
}
