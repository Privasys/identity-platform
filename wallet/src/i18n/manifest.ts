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
    version: '0629b989b64ab650',
    digests: {
        'bg': '3c45bf6050b660d1f4bba83291ffdc97c45689fca0063c6802c7aede1f44c3ee',
        'cs': '91f60ef8f22954b1a30cc63a4441ebfc8fd0a58f6f3299854cf8b122d4a95d88',
        'cy': 'c10ccfeef0847e5df86ee3d66b3ee71228c8e414f4b0f19ac01c44ef3e3726ac',
        'da': 'd68d9a24568dd168b1bdce9a81bab12b7ef8f3821b002a11115b05b2e88b913d',
        'de': '74c7bb8e8c40038a4b011b3b3a521b7b0cc3205cebf9c709e37e6ce56cd0b590',
        'el': '5cddb1939fbb9b4cf1ab049d02369646b718593ceb59959a89131ab20978e41b',
        'es': '0a355d162fde5348134fe2a971c12741e1b889a7f0a1a8c2a859b44954344d64',
        'et': 'c74d5370f3c2334a2bf247aa50e20fb8418abc1e2a81f0a43148620d4bd14e29',
        'fi': '039e34579930864112c743c1e33ca40c1748e374fecb760247aab99fdd1a98cf',
        'fr': '67d8712823a018209ee5d50b170e8002ebd35bdb719e7e4060903171992e0d68',
        'ga': '0d97de30bc06425f2adced2a961ab745f44f171a86ca49990b1a660680d4495c',
        'hr': '1a04f3b76330d830a70720d61b51b03089c3dfda6d8de325c6c09bc3da7ee5bd',
        'hu': 'd0e9d2db1ee8cd9cbb11bcf03c8a757deb11e0f22137348ff21f3162c286a909',
        'it': '2bb3106f2bca3b2e55f0532a37d9864758382a4de1513fb4e129c850969c63c4',
        'lt': '727c5668a55cecb7704bf42393556e66a46e2fe8998de23e0d0534af36632462',
        'lv': 'f079b71d24c9e6424fb3c6a7e6254c679be189253e7ce869d95518f5455b7dbc',
        'mt': '715b9149ff5474ad437ec5b9105269e924a555ad66f6b4e70f064045bc4fe450',
        'nl': 'e321df57548e84dc76d18bee654ac791c8043cdc51187250a732288ea2fa56f0',
        'pl': '9dcf7ad706c63046a38b92369aea445247c77bd902de51c817d8a50466694aa9',
        'pt': '991a2be88de25b780c0508e2379d2a50144dad31961f28b0fb04147c764f3bf7',
        'ro': '6a9fd2e3f7c2e4205d70a0572e2efcc6be4314b165eb5064747565b1db7b3bde',
        'sk': 'b34df901b83a73475523b4e589bb190fc8294d44d0e7eb723ccfcdff67a5a42f',
        'sl': 'ce58fde78297454ed2847a37dd11df5b882e4b7f08290185f66950e452e57042',
        'sv': '5de92fa853802be1adb61ba4d9df901b23e55369c75751c0232844620f438798',
    },
};
