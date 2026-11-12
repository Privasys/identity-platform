// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Check the chip-placement list before it is signed and served.
 *
 * The list tells a holder where on their document to lay their phone. The
 * wallet drops a rule it cannot read, so a typo here does not break anything
 * loudly: the rule simply stops applying. This is where it is caught.
 *
 * It also holds the one rule that matters most: every entry names the page
 * that states it. An entry without a source is a guess, and a guess sends
 * people to the wrong cover.
 *
 * CommonJS so both the deploy workflow and the wallet's jest suite run this
 * very file (wallet/src/__tests__/chip-placement-validate.test.ts).
 *
 *   node validate.cjs ../../wallet/src/services/chip-placement.data.json
 */

const SCHEMA = 'privasys.wallet.chip-placement/1';
const POSITIONS = ['back-cover', 'front-cover', 'photo-page', 'card'];
const MONTH = /^\d{4}-(0[1-9]|1[0-2])$/;

/** Problems found, in the order they were found. Empty means publishable. */
function validatePlacement(doc, now = new Date()) {
    const errors = [];
    const fail = (m) => errors.push(m);

    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return ['not a JSON object'];
    if (doc.schema !== SCHEMA) fail(`schema must be ${JSON.stringify(SCHEMA)}, got ${JSON.stringify(doc.schema)}`);

    const issued = Date.parse(String(doc.issuedAt ?? ''));
    if (!Number.isFinite(issued)) {
        fail(`issuedAt must be an ISO-8601 instant, got ${JSON.stringify(doc.issuedAt)}`);
    } else if (issued > now.getTime() + 5 * 60_000) {
        // A wallet only takes a list newer than the one it has, so a list dated
        // ahead could not be replaced until real time caught up with it.
        fail(`issuedAt is in the future: ${doc.issuedAt}`);
    }

    const validity = doc.validity ?? {};
    if (typeof validity !== 'object' || Array.isArray(validity)) {
        fail('validity must be an object');
    } else {
        for (const [country, v] of Object.entries(validity)) {
            if (!/^[A-Z]{1,3}$/.test(country)) fail(`validity: ${JSON.stringify(country)} is not an issuing state code`);
            for (const k of ['adult', 'child']) {
                const n = v?.[k];
                if (n !== undefined && !(Number.isInteger(n) && n > 0 && n <= 20)) {
                    fail(`validity.${country}.${k} must be a whole number of years, got ${JSON.stringify(n)}`);
                }
            }
        }
    }

    if (!Array.isArray(doc.rules)) {
        fail('rules must be an array');
        return errors;
    }
    doc.rules.forEach((r, i) => {
        const at = `rules[${i}]`;
        if (!r || typeof r !== 'object') return fail(`${at}: not an object`);
        if (r.document !== 'passport' && r.document !== 'id-card') {
            fail(`${at}: document must be "passport" or "id-card", got ${JSON.stringify(r.document)}`);
        }
        if (typeof r.country !== 'string' || !/^[A-Z]{1,3}$/.test(r.country)) {
            fail(`${at}: country must be the issuing state as the document's lines write it, got ${JSON.stringify(r.country)}`);
        }
        if (!Array.isArray(r.positions) || r.positions.length === 0) {
            fail(`${at}: positions must name at least one place`);
        } else {
            for (const p of r.positions) {
                if (!POSITIONS.includes(p)) fail(`${at}: unknown position ${JSON.stringify(p)} (known: ${POSITIONS.join(', ')})`);
            }
            if (new Set(r.positions).size !== r.positions.length) fail(`${at}: a position is listed twice`);
            const card = r.positions.includes('card');
            if (card !== (r.document === 'id-card')) fail(`${at}: "card" is for an id-card, and only for one`);
        }
        for (const k of ['issuedFrom', 'issuedTo']) {
            if (r[k] !== undefined && !(typeof r[k] === 'string' && MONTH.test(r[k]))) {
                fail(`${at}: ${k} must be YYYY-MM, got ${JSON.stringify(r[k])}`);
            }
        }
        if (typeof r.issuedFrom === 'string' && typeof r.issuedTo === 'string' && r.issuedFrom > r.issuedTo) {
            fail(`${at}: issuedFrom is after issuedTo`);
        }
        if (typeof r.source !== 'string' || !/^https:\/\/\S+$/.test(r.source)) {
            fail(`${at}: source must be the https page that states this position`);
        }
    });
    return errors;
}

module.exports = { validatePlacement, SCHEMA, POSITIONS };

if (require.main === module) {
    const { readFileSync } = require('node:fs');
    const path = process.argv[2];
    if (!path) {
        console.error('usage: node validate.cjs <chip-placement.data.json>');
        process.exit(2);
    }
    let doc;
    try {
        doc = JSON.parse(readFileSync(path, 'utf8'));
    } catch (e) {
        console.error(`${path}: not valid JSON: ${e.message}`);
        process.exit(1);
    }
    const errors = validatePlacement(doc);
    if (errors.length > 0) {
        for (const e of errors) console.error(`  ✗ ${e}`);
        process.exit(1);
    }
    console.log(`${path}: ok, ${doc.rules.length} rule(s), issued ${doc.issuedAt}`);
}
