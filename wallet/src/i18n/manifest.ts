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
    version: '06fde2b0d1fdcbe9',
    digests: {
        'bg': '683a8334bc88f967b6845ab784a38b97d5943e24e97d22a3c01368684203abb3',
        'cs': '6abc012ed6c92d9b6932cb78b6bbbdd56217666045231987bd846dd4860fedfb',
        'cy': 'aba6a5b8050695afceb48eec15f7039be35379270cebfc8a3bfb20e83ed4b006',
        'da': 'a6ae38c4a392fe3ecdecdb69a0013c00488cdabe297f3cf9aa1c9c324d37808a',
        'de': '669b171d135b8d78689e152531c5ed6ca0cd72c4a33347feb1707309126b654a',
        'el': '0a867c68b658cb35ef96d761617033c50baf027a2f846ca7bbab50f6b1958c03',
        'es': 'b49b030c66785a4b112bd57a789f04a232defdaa22e47e03fd6b0f7773a10dd0',
        'et': 'a46101752d03e3477d0c5e20fa9f811110e6fd7f2e79ff201d5d355ac2338b77',
        'fi': '1e485728b2c156e542075f4112af7cc4934d7957d3eda39cd11bcc0f87842de6',
        'fr': 'd9d610feaa54425c09511d0fbdedc927d400d549558219f93960b70ebfeb5950',
        'ga': '3d42c0ed945e7d30b761dafea60f431f7a851746b125583014f535cd8c182560',
        'hr': '1fb5716c57e08323b7a1c46292de3ab3f651072d3ac8422e104cea6a4b761c8c',
        'hu': '3a1c13e5f69aeaf0d3f728515a86ee68096359d5d496b525cc87e860bf3e5f1c',
        'it': 'f1fcc5e5278b451f8248af4b6d206a1558fde365a913ab15e5a99065fc9014eb',
        'lt': 'ec231aa3d113f5f8019cb51c6866e2228ddebffee892e2c6f2213fe542747f53',
        'lv': '6f0418f2180d25bd8812f82c8fb6a2c2395ad0bd081b76242dc52a36b874e356',
        'mt': 'e5251531923ea1177e171fbe415b747005142cc9088e1844c19303cdc5b4fefe',
        'nl': '28f9c233920457d0b6afea7585789211393d9036be6a76df627eccddbcfa1a14',
        'pl': '33c23036077e48336bd9fd5275acc9c9b43c91e8a56e0bef35ce1a218628597e',
        'pt': 'c58f33d8b67be69158a7e1c63bbe3d712ab62bc336ecc9711ad0a4754a9abcbf',
        'ro': '9ea5681902dabcfc48ddd4e700592b975a69a4df7572778f7e4a9aac780b5af0',
        'sk': '53dfc3092f98edb14c592cc4a0e127ee2b3ddde61418ebf694169e1ddf16b711',
        'sl': '18f6240a98e604fb8a12b8e34fa5f5aff297d45c69eaae5a8e0013274ca1d1d2',
        'sv': '0ece015293f80ac1999097e95f38dab81f715b1596d129dec901e11b74b2ae5e',
    },
};
