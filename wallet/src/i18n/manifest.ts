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
    version: '8526ff7ac12dc5ff',
    digests: {
        'bg': '35d067f4202605075485e7ceae26746fb9982d6057b62f0c52f1b4c3a8f51333',
        'cs': '41fa9026564797a96191b7b5a303f18d67d27dcffd7ba7dd5b4474135c6ccc03',
        'cy': '0d97c371be6fbe305145f82fec222aa6f5315811a726e498bba21f7763dab441',
        'da': '7bdd2a530af7959031210e0b8b95902e081354fd92587b744575d2d90ceacc1f',
        'de': '9647acea3e58d39ae0336f94b6e41bed61adbc95089bcac75eca73cc2f12ed50',
        'el': 'fc1d0e52382bb1dd6a0f22304f38a431f15ee0d8cc9ad452ae0f614846b7668e',
        'es': 'f4750dcaeaaea68e8f6496f8fc6e7e00548b9860d0941c20707e523c66e6ecf6',
        'et': 'd5808d41045832a5a80e9308ff80b9b67022834f10f4ee57842a3f907cfe47f1',
        'fi': '6483379e7381057001e0d3da0b3ced5866857366e483febfa4496a02d8f01538',
        'fr': '32ac3155fbf6cb69e62791d5d8381e3aa612dee5f510bf5fb3d60e00bac25f6b',
        'ga': '23468ccdf9a0d55118864ce4d0876202ffb3cfdce3c816092eb929822a6783d3',
        'hr': '03125cffacc3e048e09dfb6e3dbac998651a5a78a77b05865793632cde4a3756',
        'hu': 'ac187f9e63cb61bea5ead7fc9511a55eff7e116c8d8de4021dd1f43a96b0b32b',
        'it': 'ca7736f23e8db12b0dbf81502e59c7ac1180b1c8df5c4f346a4530cadd7732db',
        'lt': '73568273a9a2b20a20dd131dd2b382f83ebde5b24d7b7c759d1e6cfb646755f1',
        'lv': '4781cf2493e06aeae6a34efc81449b5220dc973401dd7a09d86472294b6d1d5c',
        'mt': '0879c6a6b2eefdf9e96d44cd20d89ae5cf395b62c64114d85671f60ada275525',
        'nl': '0dc7848dd8e30e37a8c0b0829a8414c219eb2bfe068b10e57d8e6493e3cfc346',
        'pl': '87febe867761c4556e4a3a16806d45041564c836b6964d725d07e262454d3e58',
        'pt': '55b838759ddad3cc013c0e6c588aad48e4e96ae95abb84db62696052b6d61e2d',
        'ro': 'fe57770aeecdaeadd2ae507f5fdb105448e055bc9534efe3ad04d20ea13118bd',
        'sk': '4721a343aaa1a7eeb4e6f3dcdf9ac9b18e71601b68489448f1c01a61a6dbe198',
        'sl': '38c39eea6a6f5eb51889775e61908e9b52b1eb4eaa4db65600badd2f33ed5fea',
        'sv': '7c2b4a92ec9ccefe58641d889835b8b2904f2ebb25a7968c893da851f42e8ec8',
    },
};
