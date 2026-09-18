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
    version: '54d8cda34af87614',
    digests: {
        'bg': 'eb6a292f22434d7c7d45f44219df3d8d5d2b2bc4c52bfe0d9d226eb9196b1cc5',
        'cs': '788546f51481e34adca4627511146303a14d8eb656a785697c878c9f237dc156',
        'cy': '9923e986155f9686e6af5717fb8be317210f675a0c4ee4c40517c15d4c69c786',
        'da': '87b206332a25475ec645d1964ceac85d3c419308e8a4b8b8760b95340fa9ed5f',
        'de': '654f847332893128514a37ca2d2de1852f61085f3b3dcdda576441f6fc9ba981',
        'el': '9ae2a3199987d8040f8eaaff1c1fa3898a16d3b85509067772fc58d9bc2bc896',
        'es': 'e12f50d9d3e7c8b4c9b8f0b53f20a1a7210c6e130e7945ad73e091b0d967c1eb',
        'et': '6363291c461b7751a01b5e5fae83507ab523c4af72cdcf74bf67da8d845fcbb3',
        'fi': '0092e1af1ae56c090228d6cdc586b58601817fdc489212646e60a0ebceddd3d4',
        'fr': '61e8580fb4cbe7116f314c8c3219cf9db20b8c3f905d83da3d660b494144a802',
        'ga': 'd7c63ef45f02a0fef95dbba15eea2676da86390fc784ba54b4771b3a42be1271',
        'hr': '501c6240bd306dcb47e01a2f3dd701545a5db1ac06d0969bbf4565f6007b358a',
        'hu': '2b2e4e551cd0de1cd63fe247b061e449ef4cc14e4e9b4cc1381645a24e7a82a9',
        'it': 'ceda944fb4a9568d7b52aa9ebc03435be6e11b580cbbaa972906b2c9ae81b4eb',
        'lt': '4cbd0014335b26497c745333b2c786ddc5178b0ac09a407c6eba68b74cc3ec86',
        'lv': 'e3dc33a6fc1120150cbe21625ab4075e6466d835dc1cc67110c09a2e7a1291eb',
        'mt': '59db267af7a1e7b3783c84b8f31dd967d4678ca86e4aa40f0c37a6fff5d74ea0',
        'nl': '87e9d4c3f61f403ae5b2213b04eb5dc9af886313c6ad27c6299715ba33619b53',
        'pl': '1da85b69f19718230bed6cfd17aa4ef4b31b06c75a927a6d4aabbf3de5fdbe04',
        'pt': '10acc93dc2af8d05c00cb9f576c35030a50c6091a34466eae8e21da42b479108',
        'ro': '1db81c66fe5b836f202f3a0df78b5b86497cf18f2399c2e08fded17d5d0a63bf',
        'sk': 'a69384c264ecc6c772bfc9647d989db0b6b584ded9c17becae63d236c2364d3b',
        'sl': '8a17f51210c20cf2dd0f01e549edae38ad3554d49666b0809609d0afe6e71324',
        'sv': '24c2b10a4a6845532deb17f5ab6aa40323e3c491c570473acda73a4e3b4b1661',
    },
};
