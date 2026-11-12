// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Build the list the wallet reads from the files people write.
 *
 *   node build.cjs           writes wallet/src/services/chip-placement.data.json
 *   node build.cjs --check   fails if that file is not what countries/ builds
 *
 * countries/ carries everything a reviewer needs: the source, the sentence it
 * rests on, the day it was read, notes. The wallet needs none of that to decide
 * where to send a phone, so the built list carries the bare rule and nothing
 * else. It is the one file compiled into the app and, signed, served from
 * privasys.id.
 *
 * `documented` rules go to `rules`. `inferred` ones go to `suggestions`, a part
 * of the list a wallet reads only once it can word them as "try this first";
 * a wallet that cannot simply does not see them.
 *
 * The list is re-dated only when its content changes, so building twice in a
 * row changes nothing.
 */

const { readFileSync, readdirSync, writeFileSync } = require('node:fs');
const path = require('node:path');

const { validateCountry, validatePlacement, SCHEMA } = require('./validate.cjs');

const COUNTRIES = path.join(__dirname, 'countries');
const OUT = path.join(__dirname, '..', 'wallet', 'src', 'services', 'chip-placement.data.json');

/** The bare rule: which document, of which state, issued when, to try where. */
function bare(country, r) {
    const out = { document: r.document, country };
    if (r.issuedFrom) out.issuedFrom = r.issuedFrom;
    if (r.issuedTo) out.issuedTo = r.issuedTo;
    out.positions = r.positions;
    return out;
}

/** Everything but the date, from countries/. Throws on the first bad file. */
function buildContent(dir = COUNTRIES) {
    const validity = {};
    const rules = [];
    const suggestions = [];
    for (const f of readdirSync(dir).filter((n) => n.endsWith('.json')).sort()) {
        const code = f.replace(/\.json$/, '');
        const file = JSON.parse(readFileSync(path.join(dir, f), 'utf8'));
        const errors = validateCountry(file, code);
        if (errors.length > 0) throw new Error(`countries/${f}:\n  ${errors.join('\n  ')}`);
        if (file.validity && Object.keys(file.validity).length > 0) validity[code] = file.validity;
        for (const r of file.rules) (r.evidence === 'inferred' ? suggestions : rules).push(bare(code, r));
    }
    return { validity, rules, suggestions };
}

/** One rule per line: small to ship, and a change still reads in a diff. */
function serialise(doc) {
    const lines = (list) => list.map((r) => '    ' + JSON.stringify(r)).join(',\n');
    return [
        '{',
        `  "schema": ${JSON.stringify(doc.schema)},`,
        `  "issuedAt": ${JSON.stringify(doc.issuedAt)},`,
        `  "validity": ${JSON.stringify(doc.validity)},`,
        `  "rules": [\n${lines(doc.rules)}\n  ],`,
        `  "suggestions": [${doc.suggestions.length ? '\n' + lines(doc.suggestions) + '\n  ' : ''}]`,
        '}',
        '',
    ].join('\n');
}

function readExisting() {
    try {
        return JSON.parse(readFileSync(OUT, 'utf8'));
    } catch {
        return null;
    }
}

const sameContent = (a, b) =>
    !!a && JSON.stringify([a.validity ?? {}, a.rules ?? [], a.suggestions ?? []]) === JSON.stringify([b.validity, b.rules, b.suggestions]);

module.exports = { buildContent, sameContent, serialise };

if (require.main === module) {
    const content = buildContent();
    const existing = readExisting();
    const upToDate = sameContent(existing, content);

    if (process.argv.includes('--check')) {
        if (!upToDate) {
            console.error('wallet/src/services/chip-placement.data.json is not what countries/ builds.');
            console.error('Run: node chip-placement/build.cjs');
            process.exit(1);
        }
        console.log('built list is up to date');
        process.exit(0);
    }

    const doc = {
        schema: SCHEMA,
        // Whole seconds, so the date reads the same everywhere it is printed.
        issuedAt: upToDate ? existing.issuedAt : new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
        ...content,
    };
    const errors = validatePlacement(doc);
    if (errors.length > 0) {
        for (const e of errors) console.error(`  ✗ ${e}`);
        process.exit(1);
    }
    writeFileSync(OUT, serialise(doc));
    console.log(`${upToDate ? 'unchanged' : 'written'}: ${doc.rules.length} rule(s), ${doc.suggestions.length} suggestion(s), issued ${doc.issuedAt}`);
}
