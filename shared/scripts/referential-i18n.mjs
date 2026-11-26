// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Generates the per-language copies of the coded value sets, served by the
 * IdP at /referential/<name>.json?lang=<tag>:
 *
 *   referential/country.json              ISO 3166-1 alpha-2 (billing_country)
 *   referential/i18n/<name>/<lang>.json   nationality, country, locale
 *
 * Values are codes (stored and disclosed as such); labels are the long name in
 * the holder's language, from the Unicode CLDR data in Node's ICU, so nobody
 * translates 250 country names by hand and the wallet bundles none of it.
 *
 * Run from auth/shared:  node scripts/referential-i18n.mjs
 * Then copy referential/ into the IdP (go generate ./internal/attributes/ in idp).
 * Needs a Node with full ICU (the default since Node 13).
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'referential');

// The wallet's languages (wallet/src/i18n/locales), English as plain "en".
const LANGS = [
    'en', 'bg', 'cs', 'cy', 'da', 'de', 'el', 'es', 'et', 'fi', 'fr', 'ga', 'hr',
    'hu', 'it', 'lt', 'lv', 'mt', 'nl', 'pl', 'pt', 'ro', 'sk', 'sl', 'sv',
];

// ISO 3166-1 alpha-3 → alpha-2 for the nationality list. CLDR names regions
// by alpha-2 only.
const A3_TO_A2 = {
    AFG: 'AF', ALB: 'AL', DZA: 'DZ', AND: 'AD', AGO: 'AO', ATG: 'AG', ARG: 'AR', ARM: 'AM', AUS: 'AU', AUT: 'AT',
    AZE: 'AZ', BHS: 'BS', BHR: 'BH', BGD: 'BD', BRB: 'BB', BLR: 'BY', BEL: 'BE', BLZ: 'BZ', BEN: 'BJ', BTN: 'BT',
    BOL: 'BO', BIH: 'BA', BWA: 'BW', BRA: 'BR', BRN: 'BN', BGR: 'BG', BFA: 'BF', BDI: 'BI', CPV: 'CV', KHM: 'KH',
    CMR: 'CM', CAN: 'CA', CAF: 'CF', TCD: 'TD', CHL: 'CL', CHN: 'CN', COL: 'CO', COM: 'KM', COG: 'CG', COD: 'CD',
    CRI: 'CR', CIV: 'CI', HRV: 'HR', CUB: 'CU', CYP: 'CY', CZE: 'CZ', DNK: 'DK', DJI: 'DJ', DMA: 'DM', DOM: 'DO',
    ECU: 'EC', EGY: 'EG', SLV: 'SV', GNQ: 'GQ', ERI: 'ER', EST: 'EE', SWZ: 'SZ', ETH: 'ET', FJI: 'FJ', FIN: 'FI',
    FRA: 'FR', GAB: 'GA', GMB: 'GM', GEO: 'GE', DEU: 'DE', GHA: 'GH', GRC: 'GR', GRD: 'GD', GTM: 'GT', GIN: 'GN',
    GNB: 'GW', GUY: 'GY', HTI: 'HT', HND: 'HN', HUN: 'HU', ISL: 'IS', IND: 'IN', IDN: 'ID', IRN: 'IR', IRQ: 'IQ',
    IRL: 'IE', ISR: 'IL', ITA: 'IT', JAM: 'JM', JPN: 'JP', JOR: 'JO', KAZ: 'KZ', KEN: 'KE', KIR: 'KI', PRK: 'KP',
    KOR: 'KR', KWT: 'KW', KGZ: 'KG', LAO: 'LA', LVA: 'LV', LBN: 'LB', LSO: 'LS', LBR: 'LR', LBY: 'LY', LIE: 'LI',
    LTU: 'LT', LUX: 'LU', MDG: 'MG', MWI: 'MW', MYS: 'MY', MDV: 'MV', MLI: 'ML', MLT: 'MT', MHL: 'MH', MRT: 'MR',
    MUS: 'MU', MEX: 'MX', FSM: 'FM', MDA: 'MD', MCO: 'MC', MNG: 'MN', MNE: 'ME', MAR: 'MA', MOZ: 'MZ', MMR: 'MM',
    NAM: 'NA', NRU: 'NR', NPL: 'NP', NLD: 'NL', NZL: 'NZ', NIC: 'NI', NER: 'NE', NGA: 'NG', MKD: 'MK', NOR: 'NO',
    OMN: 'OM', PAK: 'PK', PLW: 'PW', PSE: 'PS', PAN: 'PA', PNG: 'PG', PRY: 'PY', PER: 'PE', PHL: 'PH', POL: 'PL',
    PRT: 'PT', QAT: 'QA', ROU: 'RO', RUS: 'RU', RWA: 'RW', KNA: 'KN', LCA: 'LC', VCT: 'VC', WSM: 'WS', SMR: 'SM',
    STP: 'ST', SAU: 'SA', SEN: 'SN', SRB: 'RS', SYC: 'SC', SLE: 'SL', SGP: 'SG', SVK: 'SK', SVN: 'SI', SLB: 'SB',
    SOM: 'SO', ZAF: 'ZA', SSD: 'SS', ESP: 'ES', LKA: 'LK', SDN: 'SD', SUR: 'SR', SWE: 'SE', CHE: 'CH', SYR: 'SY',
    TWN: 'TW', TJK: 'TJ', TZA: 'TZ', THA: 'TH', TLS: 'TL', TGO: 'TG', TON: 'TO', TTO: 'TT', TUN: 'TN', TUR: 'TR',
    TKM: 'TM', TUV: 'TV', UGA: 'UG', UKR: 'UA', ARE: 'AE', GBR: 'GB', USA: 'US', URY: 'UY', UZB: 'UZ', VUT: 'VU',
    VAT: 'VA', VEN: 'VE', VNM: 'VN', YEM: 'YE', ZMB: 'ZM', ZWE: 'ZW',
};

// CLDR region codes that are not ISO 3166-1 alpha-2 countries.
const NOT_ISO = new Set(['AC', 'CP', 'CQ', 'DG', 'EA', 'EU', 'EZ', 'IC', 'QO', 'TA', 'UN', 'XA', 'XB', 'XK', 'ZZ']);

const read = (name) => JSON.parse(readFileSync(join(ROOT, `${name}.json`), 'utf8'));
const write = (rel, doc) => {
    const path = join(ROOT, rel);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(doc, null, 2) + '\n');
};
const sorted = (lang, values) => values.sort((a, b) => new Intl.Collator(lang).compare(a.label, b.label));

// ── ISO 3166-1 alpha-2, from every two-letter region CLDR names ─────────────
const enRegion = new Intl.DisplayNames(['en'], { type: 'region', fallback: 'none' });
const A2 = [];
for (let a = 65; a <= 90; a++) {
    for (let b = 65; b <= 90; b++) {
        const code = String.fromCharCode(a, b);
        // CLDR still names retired codes (DD, YU, ZR, ...) as aliases of the
        // current ones; only a code that canonicalises to itself is current.
        const current = Intl.getCanonicalLocales(`und-${code}`)[0].split('-')[1] === code;
        if (!NOT_ISO.has(code) && current && enRegion.of(code)) A2.push(code);
    }
}
if (A2.length !== 249) throw new Error(`expected the 249 ISO 3166-1 alpha-2 codes, got ${A2.length}`);

// ── Check the alpha-3 mapping against the hand-written English labels ──────
const nationality = read('nationality');
const unmapped = nationality.values.filter((v) => !A3_TO_A2[v.value] || !A2.includes(A3_TO_A2[v.value]));
if (unmapped.length) throw new Error(`no alpha-2 for: ${unmapped.map((v) => v.value).join(', ')}`);
const norm = (s) => s.toLowerCase().normalize('NFD').replace(/[^a-z]/g, '');
const differ = nationality.values.filter((v) => {
    const cldr = norm(enRegion.of(A3_TO_A2[v.value]));
    const mine = norm(v.label);
    return !cldr.includes(mine.slice(0, 5)) && !mine.includes(cldr.slice(0, 5));
});
for (const v of differ) console.log(`check: ${v.value} "${v.label}" vs CLDR "${enRegion.of(A3_TO_A2[v.value])}"`);

// ── Base country list (English) ─────────────────────────────────────────────
write('country.json', {
    $comment: "Enumerated value set for the canonical 'billing_country' attribute. Values are ISO 3166-1 alpha-2 codes (as card networks report them). Generated by scripts/referential-i18n.mjs from CLDR; served by the IdP at /referential/country.json, with ?lang=<tag> for the names in another language (i18n/country/<lang>.json).",
    version: 1,
    values: sorted('en', A2.map((code) => ({ value: code, label: enRegion.of(code) }))),
});

// ── Per-language copies ──────────────────────────────────────────────────────
const locale = read('locale');
for (const lang of LANGS) {
    const region = new Intl.DisplayNames([lang], { type: 'region' });
    const language = new Intl.DisplayNames([lang], { type: 'language' });
    const note = (name) => `Generated by scripts/referential-i18n.mjs from CLDR: the ${name} value set with labels in '${lang}'. Values match ${name}.json; only the labels differ.`;
    write(`i18n/nationality/${lang}.json`, {
        $comment: note('nationality'),
        version: nationality.version,
        values: sorted(lang, nationality.values.map((v) => ({ value: v.value, label: region.of(A3_TO_A2[v.value]) }))),
    });
    write(`i18n/country/${lang}.json`, {
        $comment: note('country'),
        version: 1,
        values: sorted(lang, A2.map((code) => ({ value: code, label: region.of(code) }))),
    });
    // Languages keep the list's own order (each language, then its variants)
    // but name each in the holder's language.
    write(`i18n/locale/${lang}.json`, {
        $comment: note('locale'),
        version: locale.version,
        values: locale.values.map((v) => ({ value: v.value, label: language.of(v.value) })),
    });
}
console.log(`wrote country.json and ${LANGS.length} languages × 3 value sets`);
