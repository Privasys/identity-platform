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
    version: '7c2190dd2169c256',
    digests: {
        'bg': '9346a82eb67a8e27e88cf21660590fb9e65255fd6b222c6bc8fe4df7980a87dc',
        'cs': '2fa6e79cfafcd49035ace13bfc94ceff40689067f19400d321cd436d61e65fcc',
        'cy': 'da1929f9099d87c034d6139d855986e639203f862e4413868730b8092209fa49',
        'da': 'f8001bf90c2c5680f61a3498645a529f61ef056956bdb847720ee31c95ed1850',
        'de': '1bba0b049798a4f79d23d46a17e869a6cde8265de74741184dab0562f49cebe0',
        'el': 'e7970e89249dc914a496b18512d0a35c62db9c659d7cec2f9fd39b42c3229b32',
        'es': '1f4fb7ea0fee9641bfbb9c903bb79abc5155bffc37510a0832a36a314bd1e63c',
        'et': 'd99f34641bea82f94e893f028ee7de14e9bfc709d07f35f0a4a26c30ae351502',
        'fi': '130addf51dc4e0744a6fa4cae4f240cca3d67a6926bc2197902e5049a8c1db38',
        'fr': '5b6d632eeeb3c74d9e5c046fe4c181856535d2175938c8b87b607f92bde8645b',
        'ga': 'de95ed6e5c35dd6d07e78e481d85f05bfd6c70c1be0df61c9e4885eb43b5c676',
        'hr': '2089818179da88bc46aacdda7646f2290d67b9f4ad56f315fa9dbf21dc0c6e8f',
        'hu': '7d18e0a8bcc4edf1f404603b8b7d03c65fba12c0db49ff468e9437963609c67f',
        'it': 'f9a7286d865d9f7bea108651fac4b781f1a76245c0481071c7b7ef811d66feab',
        'lt': 'f13500c75a2b1e1e920436139386df4c36c22460aee8b03fcb5fdf15334d8e3a',
        'lv': '013ca3dbcc19f26834f05f5e29ae2d6b17bc82551bae5a9141f7aaf2ae3f3d59',
        'mt': '0c401119f4ff0ed5fe616b8702133806630dfe28e8c2bb8eb92591fb319b6977',
        'nl': 'b6207f7ff67fd2bcd472367646d212b6a6e0abea709057526e5e77376d5397bd',
        'pl': '236d775b9817a1bd63f0924202a8d32d3c1b153f7d1b711d238b904fbbb0fb60',
        'pt': '601681b1067dacc84a7a3ac76d58ccde44e7ad829aeb57de4a33ba0e5ca1e06d',
        'ro': '1cdfbf55334802855c5cbe112c7fc1ecb796a4155393a9254e175f3fded54865',
        'sk': 'd7ad857702011fb69dd45fa5d1a94a327447950b73f499afc567172838bd5a39',
        'sl': 'b31e65231416cf76ba8b663c995a6d2426de9001e15b21616acee87b976a71a4',
        'sv': 'ed072213e8b01556ba57497166e2a35716035a277504e1888cb9c7a8f2e53f3b',
    },
};
