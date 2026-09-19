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
    version: 'db4bcaae1050609c',
    digests: {
        'bg': 'e3fc31f901f4177d816a42dafe3c59a66b573855919f671e8f13880ea1499089',
        'cs': 'a900f566502bc7701bd8fa00f57ef6f7a612805a1ffb9ab63622b2ac1f818252',
        'cy': '8f1b98ddb003b8b73af83bf12d83b573d54f91581eb0262f208941362af868b2',
        'da': '002ddc8c0f9f22665a4c744c6ee596280a4628ba03cf25e50c413adf68b70c09',
        'de': '15b7c97f11f6a056f042533974ce2c36597aba76eab78ade397902354b23613c',
        'el': 'ce89a68af88a4fa7c36a8f07aa3da4eb374fad032841217616e74ea266bd5789',
        'es': 'ea7a51d1fbf3d1cc597e174347ae9cc300b0b469f567e7c63e85d1da51694820',
        'et': '669a1be8395e2051039452924f8383bef91d45905803e2c163e6915aaafa10a9',
        'fi': 'd3d624bf8841d712578e4d7202cb539b79b97b15b0f655bb344ac16e2ed69788',
        'fr': '258e53398e1915e5ee7881b3590cf9bf62bc6f86f4fb67db9ec9a741b17982e9',
        'ga': 'ab40b9c9253d37c3be080e307632a1842034188435f1cb4b3fa7bfea82f3cf21',
        'hr': '908eb1c912501f4cb26b7b5f2d1ca95cb1154e9556c534a9e53ada95b2d34b7d',
        'hu': '131fd71bb9a81261dbf467c38f428425aaa36e12e6dd288947fda4d905e5ce74',
        'it': '6334aca2d64b82e60a83b79ef18c505c946dc9a07128d55c88c4faeed22812da',
        'lt': 'f9f77cbc0c60d6ccf50e1d635844cf6b2cd8511a5e34e98709992abb75b91410',
        'lv': 'e11798fc24cf5ca71ccb687dd3746bcc280682cac74760c289e622c4233730db',
        'mt': 'ca8e7b60539c46803c77903f7dc36a8464012da721057968481c0f0ade70dad9',
        'nl': '182978f9b12b47c5969cf36767029c4459bb5e36ae797073334a95fde5b12051',
        'pl': 'ec80bb6df08263f887f0830ab8344f7f02163a6b3181b6199aaf23c47d5f7a7e',
        'pt': '786451ea7e1e715796822d07d019287e3825ea9e02321cdb3adaa4de4e76823f',
        'ro': 'b9d438a1868a1113f0e82ac15e8f55bcdae67077a41ba2763fcc94986d519b06',
        'sk': '33a0b57b09dfe70790e74443a82fe3ee1540a93dd8f4ba6f9ace1aeb6468bc1f',
        'sl': '3d32d7199ba09cb40bfca34a80091eea5f5ce434da046235627aef91ce833af7',
        'sv': '793befd0672ba53d904f628bdd5d08abd6e5569c1f843ad904265180fe3259c1',
    },
};
