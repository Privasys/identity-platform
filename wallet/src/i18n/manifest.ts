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
    version: '4b8c5b1e36f451bf',
    digests: {
        'bg': 'b25e968520fe62d8128efbf3b14775e47977579596ade4a68320911d8e7c29bb',
        'cs': '55088edfb3737b393c5ec6fde04ef2ee77c3705d6f57aeccce55082f552c8027',
        'cy': '54378ea8f6359f401a371789bff27917da090042339c901c1407169bd383ed6e',
        'da': 'ada9cf1bac4edaa71b03aea5b4bd8d021b094935809bc73ea1d8a2d5c1e745b4',
        'de': 'd5451a21666c968cd1e4d7b97d761138f7e55385212e8bb9752c20163cb133dd',
        'el': 'cdf49f98f1980c5280388acf09ba174eb89cc4b4a3d4052bb747df18b7d5f9ea',
        'es': '20161012c7fbf7a5947e09edcd96eec1047ef7bfa2348572aff56a9f7fc9c144',
        'et': '82aa3d6999d61560f9f49563875108ae032992bd566c44ce3562bdabc9b30a6a',
        'fi': 'f2670f603129be81aa9711c4f56fd2aa8d3c2d455a126e216ba176ae73abd36a',
        'fr': '6ff8a798ffb73914ac366f1e412a3b44e18cc1028367d899cc6e6db75f669231',
        'ga': '9f18376a5387039f7f726c1da66255016b21582ec28f76de97a905c3e40a3af5',
        'hr': 'bb7e7c048d44c02d003ecb0dbc5193f38dc17aa50e5b77589698bd0984dbcaea',
        'hu': '40cfd38761cbcbcf3cabfd24c5a4c13e25e93df87b943def256371abc3a59386',
        'it': '614d471c2ac60448c86810c65c01aa09b50d364e8594148089b1971c7edb3d64',
        'lt': 'a4f1de7a7866714515318746bff58ccf4aeda10deeec0921b791da02cc8a82a7',
        'lv': 'f5cb9e1a14ce39687bde37fae99b8ed7d24437e43f0fa8219c18e5dcda2d0a74',
        'mt': '9812be2e33d5b79b54686f7fcfc6dd071519b87615b286bcf0388d4c4b87c76e',
        'nl': '51f06d3ceb570a2202f19eaf44c56a741db163f605165170eeae8c7630cabf0d',
        'pl': '49f832a6d5038981dd52e0591085a304c34227c87678a59323e75234c0bbe979',
        'pt': '528aa983fa72b6491c72591dcbed6aa97460457417f82960ba834c46614826c4',
        'ro': 'e4a4ff47b39d0641c1de2af0a296a6e8c3fbaa3ac58fffb3f688e9ccc9a0e0ce',
        'sk': '67e4a9cfdc15c91c5824ffa7aef2fec5f25b9309253de6be6e08ff29a4e28c3b',
        'sl': '119143e4c43796a1f737625d70f77f4a4f5ae5f0fd44c92dfa67c6fba70bc414',
        'sv': 'b89fa84219a7759ed24ff357ef63c1c9979fc1680ae309f3be2ec0aae5ae6b93',
    },
};
