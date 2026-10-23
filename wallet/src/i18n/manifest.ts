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
    version: 'c379382dc2f5ee1f',
    digests: {
        'bg': 'e37e3c4254700c16816085b5aa5dc485cd0c169c3c0ca0e19f1f1cc78be21b3d',
        'cs': 'ab7f5f465329536f69e396fbaf38d44c5c744d81689401f0dff4044f8e8cc73c',
        'cy': '4ab7ce5eebdc8afa2d378ef32e4d5425898b17aa95d5c0bd2c2d42fd4cc7740a',
        'da': '5a7aa48f4f4314ff65b54a4e667dc6403c9a66cde0cf4db685dd064393d70548',
        'de': 'acc57f79bbb4db02f48ad4cc0c2a9b7e07fb975e006addde0a9d0c02e0f2ee97',
        'el': '1e849440be2f324e5e526a9026b117abd2297ee2c539985b12b3a90aea7f782a',
        'es': 'fa2c7dcc03092cb67f6f0a9994dd312c9a894bb6e60f0d38b523183ebb790954',
        'et': 'fd7b5151b878824dbe40f54cb01afbc5390b81d72436397e437e456b0a80b54d',
        'fi': 'b6da5300e1f7761fc786a4e5bf2c171ee3904eb520892abf886fa840bc13712c',
        'fr': '60605c1d72ecb7162bb569440eaeb0c91a5c785a0896fa297df441d46f3f6b6e',
        'ga': '73cd44c6a9ddddebd1b585b3748403d283fca32027e3e5ea04e4a4d020e11afd',
        'hr': '6fa5b01929d9a817eec6cc353e0a794864fdac9e4ca5654bcac0f914832691ce',
        'hu': 'b22e2a42600e5bf476f7cc6dd38200d5da9ff3b5bc664fcf122c9eede2d63347',
        'it': '6125137a8cf315ef506a849684904b8f569de5df8238f4afd23ebf1770d4669b',
        'lt': 'eb86d13798f2bd74ef1e225c19ec39617b16e3e8410fa30795deae4fd52a2868',
        'lv': '1392aef940579ce62726682d869323889a6e592240f13aae65c0523cc9c8f5b4',
        'mt': '15caeb0581ee9ac8efa2add4ac8886e1d1449c61b7b1fa38d9a16b02ab9e5c06',
        'nl': 'e622a90114aeac7964640ac71fe9aa1d84427e1c5eeafe5dbcb192de78eb1ef3',
        'pl': '9a39d0f9b269c8db3d02c88347e28e2b2ee2f36868246d681261dfba35eb7e13',
        'pt': '7893129b16aede97598e77f7f16cb7a1bca51aa27ca89a0052ade71ac0ea90c6',
        'ro': '8a562d6314a273667f96291894fb0a3f2042783fe6351ec5f144542542a42c6d',
        'sk': 'd5a113b3719e99919e5e7f4b516388720cf8b0d02cb813015a8be4fbb4ebd09d',
        'sl': '48e8cda5381c8849cd12062ea7b9f0ff69bad0e9e77b2978fb5f06e56923d3b6',
        'sv': '4067c407244f9261d9f4e59e8af61cc8a2fe2d404643b33a5b240639b494c852',
    },
};
