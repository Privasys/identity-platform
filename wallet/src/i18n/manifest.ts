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
    version: '5b2fcc4eab5a06dd',
    digests: {
        'bg': 'b15d055f6b6c180beb40149a212bf50080d2c4a940bc20ce0ce0179f73d721a3',
        'cs': 'c9176cff1d7cef2235b8dcf151b80c5db8ebfafc5e6efde476e8a90abb61cad3',
        'cy': '7fc8aa519e4c077cf0ec792efce0abc64f0f300018e76bf2c41bffd4b86b530e',
        'da': '7d2e575bfa9179cd0861617ed1d33e4c9684f74e0785185b8e8f4c09aed1d5d1',
        'de': '8032896e1739872d60f230c304273b6ec83e52f7a3ddc737ba725136b36c8a93',
        'el': 'f4f2148bc96f7997531b2a859873812d000b480d39a8aebd0b172195b3cb1076',
        'es': '4d39e7db8149d4346699e9a617b50a11f1d9fee261c71bd96f9c8056f9c8223e',
        'et': 'a8038c9babb24d8e7467f49b0d8b521734af857d8d5eb80bbe02ba0fda6b1cbf',
        'fi': 'a5d53e5a69b8cfb96539a6cd58efe6d818ad7266280bc286e086a54cdd997bfc',
        'fr': '504e9fb8e9aef970b4241e4381d4b0d8b1f233f81bb649f2c95038189faa27b9',
        'ga': 'e76b90b27349993dfe77f28e1d166148a985c7d02489db4a8d8419e5c405d029',
        'hr': '008ccbc0b3875b30f7de2aa838a01da60d434a5390cd16ce22d284ce59eeef37',
        'hu': '5dcc405416c17c34407661f6d11203f81d7b2104cc528881f45b2380ebb17cd7',
        'it': '1eb8bab4a1d3f553dcdaf5a81b9ae2e6c7a18da496b71f43fd18a3e8beeec5c8',
        'lt': '92de3254b99142717ee643636eefbcabdafe092aa8edfdf2ab598887f68807a3',
        'lv': '120e870deb05d5633a773b93faa197714f7055f215adf1b18581f56564b0c903',
        'mt': 'c048664f3ee3e61b23b23d73876dedc68c2bdbd49be3eecb3a749b661687e258',
        'nl': 'c73c4019b2f652c256a2261a655b6c77e62cd006f8853c44cf487d7ff87e7375',
        'pl': 'ade45c39b05e4ce953c82dd87263ca079d7e7abb9e3a0851b4873d92e35c583f',
        'pt': '34008d73d8e85fed4fa4dfd59519e44d94297d9611dbc020c9e07ddd2da28bec',
        'ro': '6b6603d6536cbb36c42a9b820ac045f78475e3ae5d2b823ef7030e87cf6ed1c2',
        'sk': '12fdffdfb0a8678a41cc27cd04f1c6c2c5e3194ba6dfe8aef0d23df38f442478',
        'sl': 'cfab8fe6488332706891295a95ba6dde1cc372211a74703208ef49cc2bed9b52',
        'sv': '38f62298409783f89d789c505d32abbe68bcfd68450bf655a99e409d685cb78f',
    },
};
