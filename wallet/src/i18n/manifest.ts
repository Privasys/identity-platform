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
    version: 'e6f8bbcd38d37456',
    digests: {
        'bg': '3c43fe6c5ee5c86fd04dd5136f1dae42b23ffb83c86d7c8a46d1ff24abdc2873',
        'cs': '45ac1bc614469ee605a34ee8d676770c4e66b318c01feade75a45b0c0c0a1f8b',
        'cy': '25562e237370cbb97d8769719a0be6326dc83f1580d1d42449a27b63163de8fa',
        'da': '9d6054ffb2181fc6fc349c728dc662b65b96cafde03d2a666f8b0bdf81950ddb',
        'de': 'aa9fd2899c165c2a15ddc23e02a8718d064a2ab795f2ae49a2821139c9379324',
        'el': 'b11cdabbd8f2d0cf53ccc64a2a92e528032a7032c6c7175434602a1dc2905bca',
        'es': 'd71d0f099975005a4fd9834bd111838b9c2165cef1b423def5397dd9973a38fd',
        'et': 'f9ec831e8041775a0cafd8166cbb00d9c7cbe72620a3a7f47cfcf547396c2830',
        'fi': 'a9b08254c1cfede8aee68f6652364b003fd568b03b74c7e344e13c1328143df8',
        'fr': 'ffd873e4a0477b9de6718394cdf9369ea1cef5d220ffc4900d6ab7d665017fb8',
        'ga': '97b70f40603ea3c5984a100c88217c659145e5d7b58526eb641e0e638bc11c36',
        'hr': '2697ec0e948842c5516f937e971ae760bb38934faa1f968cc82bd6bebc92489f',
        'hu': '2122077d68ca1a88af0234f251196d1cde2e2b21b70bff97d66eab73d1f2c61e',
        'it': '679cd0ecb171c5ce69de31fdbfd4ba517d380cd1c2951f67c24bbc0e9dbc8759',
        'lt': 'c0a6c0ea7121bd4b6f302e05a423df67ae778348d301f5faa7a90208a783764e',
        'lv': 'ccbfa56291f0ced3bc40d5e848adba6d89f7605335a0e4edd958cf4342de1cb5',
        'mt': 'e63c4b943f4b3d5fe0a01ac653076045cb32dc17f1ba8106eea077157bb40d8b',
        'nl': '42e4e353eb7c3bed8a442e666a3ec2166e560a4d888040e7aac818342c43f44a',
        'pl': '4753ca473248eb129e3b85c7c57fe033a82c902e6709b49beff97b9d6c04f88e',
        'pt': '1061be6c58bbfa3bb57b3fe1b5ef7ec3815de4933e01a67e643db22aa5da22e2',
        'ro': '83267c85709585bdeb2ebf0b10f52d4f00521099a1c28b8b9154774a60d19a0c',
        'sk': 'b45b1eb5e18abc4ba64cabf03d4242a3b02a4509a797082aadcc926720325856',
        'sl': 'a6fce4be0a387e8063c03bddaa9ac23808f1476d38cb36e7f8e7e8249f49f82b',
        'sv': '2120704e1d505bd2b3d2064b210a97e8be224edcd456a9f48a89c2cadcff2538',
    },
};
