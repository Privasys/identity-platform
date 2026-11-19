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
    version: '2fc17130e6d13b0c',
    digests: {
        'bg': '2c50110dc5192b92da1bc9e7850ef6d64917f14a3c8fe634d01faf10283fe458',
        'cs': '747408d7d253b30315301c42aaec55eb349061876e13eea4839a11cd677b806a',
        'cy': '71f71343f72afee5515ab811e9f3b013c00563aaa98ce8f531b499ad5757b0a3',
        'da': 'ea922bde6afae529d781fe87e3eba27a4cd456132d05a85042587a4d963d4167',
        'de': '0eb1deeddf3a2e2ecd0feba7b6678f743ebca84bc660f4749b0a5fcaa1785b21',
        'el': 'e9566cb2054d49dc9ed6402307e615a92c378b2aa578f89c9ede8de00c87da49',
        'es': '7434b91c48bbcf1159ff38aadad76bc85c388574ac063b08d47f15749e213a57',
        'et': 'eae29748e4b3af7d07fec22a7d9d0616a21c2560716ea8425ad6189f2ac22790',
        'fi': '1ffd3319d442e2bd6ddfc3f083b063945331499f1d500ea2c8c8c61644ba4b25',
        'fr': '7fdd23f75d296038d778e99e01c8030c6362abf2ae7cac98a5887220e8594deb',
        'ga': '09018526ec20f967eec06ccb7b73da6dba3acfe2a59acbeeff0775178bc84de8',
        'hr': '775c60b17ff53ea7732c7b0709b3451a4351f57fe062613b400cd8d3c105e220',
        'hu': '6eeb296fd4f1f298086d2596c1020377ee0e0333f9e2212ee88c8b28ff3b1981',
        'it': '59e20ecca6737e4df02fcc8f7a0a1140a358e11925fe123752e5e5f7e3d67cad',
        'lt': '36e0ab6fd292e7f5aa915d3a61de28461953631c471a571723640a211fe87ddd',
        'lv': '0707312c191e5f04b19bd05cb6f51d0392ed0a90ff58a7fecdd387e3e4226f3d',
        'mt': '161825f178ebe86a90831c26f3dd07287ffc1a629c0de3adb18c702e07188396',
        'nl': 'e218c50011a2348ce822a275b373c403f02b829f91624ae183a6c547000a639c',
        'pl': 'f1d5e5377234664deda23f763a60fbb6ade6e7b1317107f862d9101c86ecd1a3',
        'pt': '1395318051a675b149acc90daeb1def81fadccc46ddfa428b4a1d8ad2d3ea1c0',
        'ro': '14dedca8aa5334b088b00cc7b5861edc4d984579533b63ed52ce444c67ad8509',
        'sk': '6711be8b1ed49fcb2a566fcdd910cfc889814f8dc159d6ecee16f42977c833b3',
        'sl': 'e16672679aae10a0ba7d2cb1ab5ae861d2bedebc844b55f6614e7541d115b8f5',
        'sv': 'd7f15754b8fb32daca2cde3de3db92389858597a6dd8f348f3f8536e52904294',
    },
};
