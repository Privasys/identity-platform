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
    version: '071743a044e095a3',
    digests: {
        'bg': '76b7e556b8efdb9708f01165560d6363ba2ca27e0b56c79dc6cdd7cee86804eb',
        'cs': 'e8958be12cff41b74cadd3536747238a26e129d38e273e39bcc10f10517e454b',
        'cy': '1f673ba803db9e30c1184166a9b04b5b90e1b9850abb5ab9727d08a89b6304df',
        'da': '946851613a4bd700bbc6ff4411159d14c7704fe12285e74ff32e2d79e962eb26',
        'de': '15b3648ccb4e3e27ceb1ec536433d2cf692ef4f3caf84217a07f707bb65216df',
        'el': '6b5389d06cae787dd9e2b2cb484f9c64bb19b7d0c09d512edb77e87d7ca39c58',
        'es': '1784516d7cbf3891fd3847b1db1128369b17fedb560b78a08ab6c500a4e61d45',
        'et': 'f7f06f088c291eb5abebade8a1517f60720c4211c7fa5d851ee23a22d01b571c',
        'fi': 'e7b92766dab1c963f7f271eec1d5d6974ede5625d6ea96a6d10bf893f527a283',
        'fr': 'e8db9a84fdcd86e3d7b61773e21988d0b7c827f85292083008cbc7d484565831',
        'ga': '5c0854622cdb8e1a5233678cc499b47625af9bac81e17b29dbd6341ceade9cd8',
        'hr': '9ada02a8dfe6e64cae71f06d24f948d64ec90d7e865e489bb6d98ccf9df59404',
        'hu': '176bb1240951b218c3cb5c591d6a750110aaee9de2409b49240d82480a2a18fe',
        'it': '14b6effbf44bd83d86c18f0795148b1184f9ad5d2cdc124e1a9abc3dd73a8023',
        'lt': '91c7a9535d44e2c62cfc784b35a785f76b9aab7f51bb51f80fa36404c54799ea',
        'lv': '132e496dfc5538e72f58e840d7dc264b51662c0adf7bd45bd6648f815791df56',
        'mt': '102eb40b3c0f329be14a4938eb07fa56b83c0c0d60f1fca62ae86fcaf722a79c',
        'nl': 'b52a52e109c97bd424e5cb5b675cff128e391757d1624831123239e10975f1d5',
        'pl': '3837f18fae8f60b06e408be4faf5e39a6cebbbb7cff7ad9080c64c12e8186796',
        'pt': '5f29a59f396d2c7bb913d9698ff30f19a14a901b69c0acd65a74f181820c7b05',
        'ro': '5f2e5334fb5cb81972bece3f03c9f01dc161c1b7b0a2d3a0bd1cca302a8b1b45',
        'sk': '98d68573e07d7d7f69e5bfb9cdd2d62a38e0a62605aa7679a33f5019249567c8',
        'sl': '533ab8760b7094a1a0ea58255e560114639b3f7be04f628d07d5e6ab889cbe43',
        'sv': '6fe087ebf3fc0329c5cfea3ec3b4060704cd3d60fdaa6ca6c6c1a844f87dc7c6',
    },
};
