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
    version: '1429a99446bb79ec',
    digests: {
        'bg': '9626284de2b1d1b4157e8f3d11ec7aa19ffeef6f6f68e1ff0b542e2fdf6d6c86',
        'cs': 'a24b3bc4d35fb9bfce57f9c1252e533f98b9152686062ad55a6186ddd32f9cc5',
        'cy': '5d63e255646081022393d2655936115aa57cd41aa037c1fa2bb6a1bc17b989fb',
        'da': 'c012a3e721865768afc5102cb8edcdd77737994ad433a4b6ae84ed65acd27e25',
        'de': '43fcfb3c16fa67b7fda2cab722dcbe520f18f09ef9413c3dc52ac80dc22f286c',
        'el': 'af36088fa0fefddcc85179896b9326feaed873c2b53fb3e4bdff62d805895535',
        'es': 'ce0c3bb2e2b836e7002d040919be404f5938cbb788a3202bc0c3e9559e8ca3ac',
        'et': 'e3cdf0ed95369c04cf9003da654db6f26f9c0af487721115f76a3cb36ea3b29d',
        'fi': 'f8cfc4e6c2fa6358bab6e3d1a7a17ee1797feafbc8c6414dd25d5988a8aad946',
        'fr': 'e8178ba40a650d214ff7a3f9b285db45f750b198cdf50d0ee0ad3dc22216667a',
        'ga': 'ed17c75f0d97e611741a215f8ba117821a460287bef49139895e1bc61a7704ad',
        'hr': '846e71a998499fbf118eb59543e8e35366c7f56e6fdd1d23fed3300b8ee2bd73',
        'hu': 'de18a7ce6f7193673fffd8748c18b0f9cc17ad14be5f9d4f5d530635f1f32abd',
        'it': 'bc0cfb9e5c4dc84ab67f77d20edc2a0b1ed8edf9fbe09c78c2a1f2c26c3061f5',
        'lt': 'c2e56232f3629a6af7fe9bb5bd090347eeafd92bb6c5ddcbd3a069d1f75ce446',
        'lv': 'f8e26fea2199369c7affc39f7717e57c4703852fb2add69114c8d30eebd0dfb2',
        'mt': '795108d1a91db789bf260b82738c25af46003a3c53a5e56fc44e2d17d92d1406',
        'nl': '84ae20f32c9aaa2eebf8e18ab2f15150a489f3e8e078952905aae7d6affed738',
        'pl': '1363cbeb0c8bc997439b5bd2464cc9f154b6836ad81dd6bceb6fe3c763558131',
        'pt': '4c3df26c1b27ab5571b2ef3408d122c7df052535ef2ffe29e4fc396d499f1ee1',
        'ro': 'bb9e8144a7cbba71b62bba93ab26cf123c1e402c8ae4a2f1340945552f778498',
        'sk': 'b6d42839cea965ef0d099deee273cc02c4ce86fec952f3b6f472051777746933',
        'sl': '85986912032e1911910c81691f73847c3469a55d798a04e25c142a9cd7cbc2ca',
        'sv': '0643e036b6304d43b67accd41757a340856f9aae9f7068e7b3ef5fac8fa6d4f7',
    },
};
