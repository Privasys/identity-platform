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
    version: 'd476cead7a7c68a4',
    digests: {
        'bg': 'ff87f3cc55da5ce9a98719ee815a7e9c418e2bf8f82377927131d67122bb7f5c',
        'cs': '5ae9f20dbf7976fb0821b8a594298dd9fd4008fac50e40616df89ee8f4b16590',
        'cy': 'd7bc33ed92adcff92c059cf0f03c254eaf6e2e99ad14b7e85ad36b1ad8087520',
        'da': '8f8f9d4e543bf645e8b4e6bcea776583d426e22eedfe700547e13e16e80e268f',
        'de': 'edd62bb76fd34ec8704ab7c5e733465a5a49890d1c6e45b92fc0133c101e0d43',
        'el': '6eb19e5c82641400f7313edca8c5c75f6626ed06fe02732435c8a857b578eec4',
        'es': 'ad69afd103e81c892720b4d135f5958c95b6319a00c1f8b1d2cde9212a16603a',
        'et': '0245225907148f782647e0e7afa2de0d3f49e80c51a99383ee8f0e76cb201fc5',
        'fi': 'acaf883a6a6480015d3da856c44c40b22e408603b2e6345e77c2ae4331cc2cc0',
        'fr': '36a41c45c85a445fc278d2d3755d179b71f29d01ca2f13903c80c3c62c9e50a3',
        'ga': '4f0a5c269d6902eaa8b60a244c9bffd54c89e1ea25dd9686fd24bd2ea209abb5',
        'hr': 'e7aea55ddefeb066df662376ddb77d62d34b465d2b0af162494e74af075aee36',
        'hu': '1162f771420b32d28e4e6cf7f2d71733d3d431a18517050eb7ab8401b05384ca',
        'it': 'ae7a1c90b583b08a8a49cd093f125088eb70a93562df08cb1ca23246b8580843',
        'lt': '9055392aea7818b46a08ccb04abfab688a2b944fde555f6e9bcabc942787b55e',
        'lv': 'ece9a8e13ac1cd1ee7cbc919563dab81695b11afa006a550f80fc59d27f90415',
        'mt': '2b0271a6487d0f3cc6e2e591c6f023da84ed0f1193fbfc3745b54dc7dd83db30',
        'nl': 'd01f724d0c4238f26e09e676563d98a7ef20d88bf0063b1c5caaa2592dfe8eaf',
        'pl': 'e91db22e978ab573590a292038dc9e2b6f6e4502c6c8fd5ff2ecfcd45d70e0fb',
        'pt': '23d28e388d7c6925bb152b929ffd33bde2d114795ff7aa6d987d374b4cd35d08',
        'ro': 'e1a34b5dbf4d4e07e0f9a04ddf79934c01fc75a637bbfe2b64dfb0de1a85ee26',
        'sk': '9359b5d9e548090b21f1a246a28845fb478e02b733aeb773fff206e2439137fd',
        'sl': 'e9ed2829cfc91dd945d3f887aef8ec4a2b6b7f9d9da7f9451f00bdc861186ddf',
        'sv': 'd79686cfcdeab7b0655723af45aa1784122b6f243d1533797263a9405626c774',
    },
};
