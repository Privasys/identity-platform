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
    version: 'a99dd22b21e930da',
    digests: {
        'bg': '9de7be5cee9802dee0e2db70b9196ddd8ac3308e19a4e7b047761783134aa30f',
        'cs': '5c5a90e69e16e4cad5c9fa431664de3a38f1a79ae296c28b4302e142fb11940a',
        'cy': '3ba65510ef2dd84a9eb83a41cbb20bc05f5eee20c9cb42ef7a01e25b4d3044fa',
        'da': '4af78217692a333df4b042acaafd9e9277d338cfc1532946f334022df7be30a5',
        'de': 'aaecad2b4ef346557814ed0137f1bb902ee6e4fdddcf77fa7e474182f641319e',
        'el': '5bf6c37975a66df99a5cc22ab11fde533fcf0b062eb97c75998c0cde9f11110c',
        'es': '8827b58fd92b290396747966a72b13d992a0a040cc8c9e62ce9f9debbe2a1e6d',
        'et': '696df24287e9eca22c57219401e2251d666ca3f724a695258698db6372850a12',
        'fi': '1f4c14344f4c5a7783c45f10e0a30eade119342f623bd207b966254d7957db38',
        'fr': '8ed7add6336f68b77e1f5ac8642b98154684b8040f51386962ebd2f9281e644c',
        'ga': '75e1777975e2592511442282aee40d6203a5523fbca34361547e15ec10936412',
        'hr': '401f873876ab0500db3af5e57f25937f38a1bec551ebe0f2a2d921e63056c83e',
        'hu': 'a8bf46f49cb0896285dbece011589c6e093d7df493e4d55820cfdf07195c9256',
        'it': 'e5671a09e10f2c7a138fbb52d0298bff3354b442c9fe1f90de7b19be685c0e4e',
        'lt': '2351465185c3b8cfacf71e08072ef5163f64ab01f8b09816a5b2be7067f088fb',
        'lv': 'b462e2aac263e3210be0a6be2f9c9532b47f451e89449a99b6c210edea05bd88',
        'mt': '11478a7ca439a270575ec412697b698cac41de9800c7c1c8d77ca773df7fd840',
        'nl': '6359106468a8289067eafbdb4ebe6bc6bc1bd3fbe6daf6d01d363c32a203b45b',
        'pl': '783effcec1ec52e937421d366121c7e147b030a2fb5b72bd81cbe0cc05bad966',
        'pt': 'b10b2f31301ebe5825e411a6c91b38babc6330c36dabdb69ade6c1c3c1f16a55',
        'ro': 'd6119026a870c2e7db28f0516874ae7088540025a22a1fd39b2e79c7e0266fb9',
        'sk': '0da276cd4c65861e35ae9335cd4e56271a68691e9e445f33a0aeae544da302eb',
        'sl': 'fbca0cbd9f30baa92a1706d3cb6200b26ff6f28ada20069a033fd05dcc2044de',
        'sv': 'f49b005cc04fac08d717302af4f139f8f59e321642d2c18b63587d1ae38a2e7d',
    },
};
