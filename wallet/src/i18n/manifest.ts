// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * GENERATED FILE — do not edit by hand.
 * Regenerate with `npm run i18n:manifest` after changing any locale pack.
 *
 * This is the trust root for downloaded locale packs. i18n/packs.ts refuses
 * any pack whose SHA-256 is not listed here, so a compromised CDN cannot
 * rewrite the copy on a consent screen. See i18n/packs.ts for the reasoning.
 */

export interface I18nManifest {
    /** Content-derived version; also the pack URL path segment. */
    readonly version: string;
    /** tag -> hex SHA-256 of that pack's bytes, exactly as served. */
    readonly digests: Readonly<Record<string, string>>;
}

export const I18N_MANIFEST: I18nManifest = {
    version: 'edfa220d93d0ddce',
    digests: {
        'bg': '9e674947cabe8edd8428bc9cf9ad4ca9598f17c00bb70b219b4556e1d1383328',
        'cs': '56f38458a8b27370ea71a82a06a47b66cc8d55fb094c02e1a9c34c4fead2c7c8',
        'cy': '018830f61ed9946a6a403eb910985ed8a5a00b26bf1a0082d07dc4d08e44235c',
        'da': '8d0452068e69fc3f27855c3c8f0175e22aa001e3fd0543de0ce4a76ce3ce071e',
        'de': '326709d76f285196bae5a025d5007a04e843e39f5518438786eea72fb4776ed9',
        'el': 'd07e1262cf689d9c454c1c5dcd7e2c0e1518ec1967ceee2c6a28e06fc378b11a',
        'es': 'bc22462310e2d0564d32febb81eb9cff6eaf34afc93733eb250ec6fcb85ddacb',
        'et': '891d93efeb99fe416df463960e7801f292b543af6a09664d80e31bb4b328f638',
        'fi': '43a8261b9a3cee5db678230e2f5818c40df03dcc48b597004e4e34173f6f476a',
        'fr': 'ec5988814d1e3a356acba90ca46b84eb8aa3495602325d87aba15aea4393e410',
        'ga': 'aab2fcf7f70396691637a991e0f56c4d31797acc945e0302a0d2479e0163d84d',
        'hr': '6527c3758078042e81392b0af18057b459e9d2677088619bcf9a6fc950792c4b',
        'hu': 'b7b767e58131b0649a897298a525a4b70d00a57e040b7aa7e6e94aa29d65cac1',
        'it': '62bf0c2e625fa78d96fa112cd22ec2b0a557332dcf634484e32ac7c5d3235612',
        'lt': '7ca9095595e4860051c9271df58cf8b7603056f1eecb7b13d308238ee7b366a6',
        'lv': '8cd37be3eef58de82f9ef9f3ebc88a4727371551a25020dd6ff65ff9db744688',
        'mt': '6096910ecc583be66af2fbf86cf727e116ec4af240ca0564e9caaf177668b831',
        'nl': 'c14039670ae2a18c6b4cf52f62d713008fce76a626080915309d3388c8a7f790',
        'pl': '96012b94a200d43467dffc90850e5afa7fa735dd01b785256be23dc4f7bb5fb2',
        'pt': '95a8515af0d6b0c311d0af3e64c94c836bb74694e5cd176075687e937f8f1444',
        'ro': 'df0e94a08a60171afdfe8bc32fec5090867148c2c0f019df8f4af88f2976a0d5',
        'sk': 'b347554ebecc4dad2e1b3fde4d7fe6181256d56d510c07b401988b629099d96a',
        'sl': '5a273a14275d333acd5bfaae04c0496523b61fc08c542814a0e99d603cacb0c5',
        'sv': '30ac020f42c2b6dab451c769a227a5f7e3b2f095d4d2720993ecd0d18d88cac6',
    },
};
