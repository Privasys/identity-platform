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
    version: 'f01f554b0529a3a1',
    digests: {
        'bg': '702926a341aa65d38b2387a7e5e86387c95e1a5bc7876f8cac949fe15b913f07',
        'cs': 'd18a39ebd99be855ced945eb95936b1b903e847242c8bec25b25fac7b73ab0e2',
        'cy': '5ec55afa0947ac409a300a5b67eae5f932310bfb8dd7c873a80f9491209f8069',
        'da': '20c55b4b0ee014abf465d2240e34260901dfa3d31ff582e96706519d9a3cd2aa',
        'de': 'ce23586956d8d7d1bbd2319e272255f0359972cbddaaf31d116ac634c5e9d8e3',
        'el': 'e199d7772b8482ca4aafa46d48037a0ca9b2fd61974caf73da7c07f42688d5b7',
        'es': '0862d9095605f28927d164f7acc0b4600060078b1f4cdb63817870793b35a6e4',
        'et': 'a701821d65894331238e871f356e0871e3d08d04244698dc22d3d0a0fee5b506',
        'fi': '32cbd0bf23eb4da2678eafab44ac8c60e8b69a29fda39f4b632cbefe1465a0cf',
        'fr': 'a0e2fdc154bf72cdafbee76dbb6040beb16e231e2176be65982666a8c298be7d',
        'ga': '5de7379f51ab926485db2277bcd38ef22c1385948aba96faf03134f3d9e56d6c',
        'hr': 'c5f71719d9f2488c472bd0dade7ab976e27efdc75b6953aca00cc9b07c6b9875',
        'hu': '7f3c8a7cc1d7317304eeae35738b88964f5a279f30328fccd606eb6d6869359d',
        'it': 'eace5172da5d86a3a02751735a29d861afec506bb0d2722f3f87eab945072a5c',
        'lt': 'b77919e65fa143fc6e2587a470d92cb11369cc03a505ed5be6fee2651157288d',
        'lv': 'c4a824f03f729da0038e45be762b8fabb1f31aa339ee5737783cefdcaa056c05',
        'mt': '897a84a05a0466687ab6f1923e3e935b606f2e09390858b8871e9b57d0cf5479',
        'nl': '40fe19b274e81a9591fcaef80f47666d5e7abc3f582f317654b6ece0648f86b4',
        'pl': '0a6ec5908ce2412331b24fdb89dc60e00237b87f51aaa887c81b66d90ca46dc2',
        'pt': '81864890a80b1206dce3ad60a6d87d5d7490e45ed67e668a9f25efd012fb52f3',
        'ro': '018cb69e89b2c8a9cda7b14a28c81b87c40b1ddd0185ef79a7c6fd3e1e4d30eb',
        'sk': '26c32e6eb310a6e397fe2bab575ee1dfb09c6cee418adf27eb1b816d81e43a27',
        'sl': 'f44735e3d1d8ef229059184b4d68b1760357101e8cc3dc4a2f3280e03151d6e6',
        'sv': 'f58c9f5c38ad62f67a6c48dc634b2ca0b0ff5d02506b6ae1d8065a0eaaaf51d0',
    },
};
