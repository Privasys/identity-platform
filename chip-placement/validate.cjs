// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The checks on the chip-placement list.
 *
 * Two things are checked, with two functions:
 *
 *   validateCountry   one file of countries/, as people write it: every rule
 *                     must name the page that states it, quote the sentence,
 *                     and say when it was last read.
 *   validatePlacement the list built from those files, as the wallet reads it.
 *
 * The first holds the rule the whole folder rests on. A position without a
 * source is a guess, and a guess sends people to the wrong cover.
 *
 * CommonJS, so the build, the deploy workflow and the wallet's jest suite all
 * run this very file (wallet/src/__tests__/chip-placement-validate.test.ts).
 *
 *   node validate.cjs            checks countries/ and the built list
 */

const SCHEMA = 'privasys.wallet.chip-placement/1';

// Keep in step with CHIP_POSITIONS in wallet/src/services/chip-placement.ts.
// A wallet older than a position drops the rules that use it, by design.
const POSITIONS = ['back-cover', 'front-cover', 'photo-page', 'chip-page', 'inside-back-cover', 'inside-front-cover', 'card'];

// documented: the source states where the chip is.
// inferred:   the source states something the position is deduced from (a
//             polycarbonate data page, say). Shown to the holder as a place to
//             try first, never as a fact.
const EVIDENCE = ['documented', 'inferred'];
const SOURCE_TYPES = ['government', 'printer', 'trade', 'vendor'];

const MONTH = /^\d{4}-(0[1-9]|1[0-2])$/;
const DAY = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/;
// ISO 3166-1 alpha-3, in the country files and in the built list alike. A
// document whose own lines write something else for its issuing state
// (Germany's write D) is mapped to the ISO code by the wallet when it reads it.
const ISO3 = /^[A-Z]{3}$/;

/** What a rule must get right whether it is written by hand or built. */
function checkRuleShape(r, at, fail) {
    if (r.document !== 'passport' && r.document !== 'id-card') {
        fail(`${at}: document must be "passport" or "id-card", got ${JSON.stringify(r.document)}`);
    }
    if (!Array.isArray(r.positions) || r.positions.length === 0) {
        fail(`${at}: positions must name at least one place`);
    } else {
        for (const p of r.positions) {
            if (!POSITIONS.includes(p)) fail(`${at}: unknown position ${JSON.stringify(p)} (known: ${POSITIONS.join(', ')})`);
        }
        if (new Set(r.positions).size !== r.positions.length) fail(`${at}: a position is listed twice`);
        if (r.positions.includes('card') !== (r.document === 'id-card')) fail(`${at}: "card" is for an id-card, and only for one`);
    }
    for (const k of ['issuedFrom', 'issuedTo']) {
        if (r[k] !== undefined && !(typeof r[k] === 'string' && MONTH.test(r[k]))) {
            fail(`${at}: ${k} must be YYYY-MM, got ${JSON.stringify(r[k])}`);
        }
    }
    if (typeof r.issuedFrom === 'string' && typeof r.issuedTo === 'string' && r.issuedFrom > r.issuedTo) {
        fail(`${at}: issuedFrom is after issuedTo`);
    }
}

function checkValidity(v, at, fail) {
    if (v === undefined) return;
    if (!v || typeof v !== 'object' || Array.isArray(v)) return fail(`${at}: validity must be an object`);
    for (const k of ['adult', 'child']) {
        const n = v[k];
        if (n !== undefined && !(Number.isInteger(n) && n > 0 && n <= 20)) {
            fail(`${at}: validity.${k} must be a whole number of years, got ${JSON.stringify(n)}`);
        }
    }
}

/**
 * One file of countries/. `code` is the file's name without `.json`, which must
 * be the country's ISO 3166-1 alpha-3 code.
 */
function validateCountry(file, code) {
    const errors = [];
    const fail = (m) => errors.push(m);
    if (!file || typeof file !== 'object' || Array.isArray(file)) return ['not a JSON object'];

    if (typeof file.country !== 'string' || !ISO3.test(file.country)) {
        fail(`country must be the ISO 3166-1 alpha-3 code (GBR, DEU, ...), got ${JSON.stringify(file.country)}`);
    } else if (code !== undefined && file.country !== code) {
        fail(`country is ${file.country} but the file is named ${code}.json`);
    }
    if (typeof file.name !== 'string' || !file.name.trim()) fail('name must be the country in plain words');
    checkValidity(file.validity, 'validity', fail);
    // 10 and 5 are what the wallet assumes. Writing them down again says
    // nothing, and reads as if it did.
    if (file.validity && (file.validity.adult ?? 10) === 10 && (file.validity.child ?? 5) === 5) {
        fail('validity repeats the default (adult 10, child 5): leave it out');
    }

    if (!Array.isArray(file.rules) || file.rules.length === 0) {
        fail('rules must hold at least one rule');
        return errors;
    }
    file.rules.forEach((r, i) => {
        const at = `rules[${i}]`;
        if (!r || typeof r !== 'object') return fail(`${at}: not an object`);
        checkRuleShape(r, at, fail);
        if (!EVIDENCE.includes(r.evidence)) fail(`${at}: evidence must be one of ${EVIDENCE.join(', ')}`);
        if (typeof r.source !== 'string' || !/^https:\/\/\S+$/.test(r.source)) {
            fail(`${at}: source must be the https page that states this`);
        }
        if (!SOURCE_TYPES.includes(r.sourceType)) fail(`${at}: sourceType must be one of ${SOURCE_TYPES.join(', ')}`);
        if (typeof r.quote !== 'string' || r.quote.trim().length < 10) {
            fail(`${at}: quote must be the sentence on that page that says so, word for word`);
        }
        if (typeof r.checked !== 'string' || !DAY.test(r.checked)) {
            fail(`${at}: checked must be the day the page was last read, YYYY-MM-DD`);
        }
    });
    return errors;
}

/** The built list, as the wallet reads it. Empty means publishable. */
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
            if (!ISO3.test(country)) fail(`validity: ${JSON.stringify(country)} is not an ISO 3166-1 alpha-3 code`);
            checkValidity(v, `validity.${country}`, fail);
        }
    }

    for (const list of ['rules', 'suggestions']) {
        if (list === 'suggestions' && doc[list] === undefined) continue;
        if (!Array.isArray(doc[list])) {
            fail(`${list} must be an array`);
            continue;
        }
        doc[list].forEach((r, i) => {
            const at = `${list}[${i}]`;
            if (!r || typeof r !== 'object') return fail(`${at}: not an object`);
            if (typeof r.country !== 'string' || !ISO3.test(r.country)) {
                fail(`${at}: country must be an ISO 3166-1 alpha-3 code, got ${JSON.stringify(r.country)}`);
            }
            checkRuleShape(r, at, fail);
        });
    }
    return errors;
}

module.exports = { validateCountry, validatePlacement, SCHEMA, POSITIONS, EVIDENCE };

if (require.main === module) {
    const { readFileSync, readdirSync } = require('node:fs');
    const path = require('node:path');
    const dir = path.join(__dirname, 'countries');
    let bad = 0;
    const files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
    for (const f of files) {
        let errors;
        try {
            errors = validateCountry(JSON.parse(readFileSync(path.join(dir, f), 'utf8')), f.replace(/\.json$/, ''));
        } catch (e) {
            errors = [`not valid JSON: ${e.message}`];
        }
        for (const e of errors) console.error(`  ✗ countries/${f}: ${e}`);
        bad += errors.length;
    }
    const built = process.argv[2] ?? path.join(__dirname, '..', 'wallet', 'src', 'services', 'chip-placement.data.json');
    try {
        const errors = validatePlacement(JSON.parse(readFileSync(built, 'utf8')));
        for (const e of errors) console.error(`  ✗ ${built}: ${e}`);
        bad += errors.length;
    } catch (e) {
        console.error(`  ✗ ${built}: ${e.message}`);
        bad += 1;
    }
    if (bad > 0) process.exit(1);
    console.log(`ok: ${files.length} countries, built list valid`);
}
