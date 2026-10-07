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
    version: 'c42d5606a3eabacc',
    digests: {
        'bg': '1bd667c2ba779b210e8355335caf09526d3ec18f6ac9cd3864b0ad6bd88d4d02',
        'cs': 'e3baddc8e1a0aa102f82ac4ae3af2557656d6295994798559dcba31375d0a2cf',
        'cy': 'ae297be62da07cd3ecd0d3e50470812ad6bec4dc7e01298aadb192321ca62cbe',
        'da': 'bb2abe6c9ff951107e34ed7e727e31627ed3fc0007f66dd4aa7725b9c48247d1',
        'de': '5b68890cbb1bed69a28a71e62f49c635c28d39e4b9464ce667df94bd944757d2',
        'el': '688f71a43f2ceceea6f7f825e7fea0d69fca9d2bb638822f4158b55de2e0f3c5',
        'es': 'ce1eb94a785fabd09074c3fdb2b6716f1e9dfb4e08c073515e072c7faef79a44',
        'et': '90c367fe03bd2ae86b053e2f67f9306e9a3aaed150714ed5c46225533056013b',
        'fi': 'f2192ca229313c8125a2559fe566e00ccf7837d22f8391b91f83980dd392694d',
        'fr': '516256ff64c80778c2b85a7aae5c4e92d6c47b42de1dfac03be9b76a1e650e8b',
        'ga': 'a776d0e9fc1edc029baa185f82fee28c97c518e04bf4142280f8303bbb56cc64',
        'hr': 'b341ad3938d2e2cbad06dea2d169119f4dcbf3bfb9512020fe28ce4e4d8b8019',
        'hu': '988c67290ebf4e91531f2c10a599e409d2bd1e2c31e515c67782a4a1db12aba1',
        'it': '682a8a4106f143398fd9bbec4daf9b2ca550ec6fea5d99f6fec41924df93e31d',
        'lt': '9e91feee69c10194b87941a5d37870c63c582a18b0b0fc9f19aac8043c42b7da',
        'lv': 'f388c0a48d30d3e45244be801b166aa478630d1897b1caddd7a1065a4119cddd',
        'mt': '917dc68e4e8e101e5f2d35860404dbe3ec4555e33ea905377439cc077b4aae37',
        'nl': '4053db236f8210baa9a58cc1207cbd52e490589dea4c2a8d63d395714a5694e8',
        'pl': '1971031a4ee9204e274d669288e6dfccebf2d9ac590d6e33149460db6cc8bf74',
        'pt': '37781ddcdc2ac0aa75718263abc2408a9fe15232b133e9ccd5f2eca8b435a84a',
        'ro': '70a6b53dc1c7c12da47b0be7e9347923c6d2964d27d5a7fc4a8788a68de6c017',
        'sk': '69125dfadfb773d045606c1d2b8fb10be1f5a126b417e79ae0bcf563a13cfc58',
        'sl': '898c9f8772afe1ae9725edf428fe10a9d0eae1e068f734447bf0e148e6c3f8c4',
        'sv': '143acf5e3f30b135bcdb6ce587fe80e6400e5dc2f20eb69a85fb7aa4a8318e63',
    },
};
