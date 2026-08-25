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
    version: 'faff26dd92cff017',
    digests: {
        'bg': '9208e70c8266efd7058e118d10aec6fb363458c12ffa6c9353c8fc8018521dff',
        'cs': '142b95bf958232555f437be22543aca0f5c24f8623bc8759b8626a854e9dfd41',
        'cy': '35be1633c6b403f978e05abc342131419c647c9a753a5778e38accc2488fcb7e',
        'da': '212988f4c844c29c81e0fb3c217b65eb6cb56d946e48e54aaac79daa78382ebb',
        'de': '275c3c2f1a8f258770a3f3430c422297ca381b7f24ce0c3e8ac70327c6544884',
        'el': '85658a0e54a2fddfa0d04bc0570d96126ef3d3fba6654cf3daa9faf853a5eaff',
        'es': 'd9b6d2a063d6189ce9e7716e2495b5828c9b553c179fe84a58dd60576ad5444a',
        'et': '1bef2d4899c7e4d26fd27f29c8c7612b37946b8e97d27aa369f43f3fe5876778',
        'fi': '236247bae4a5768f7b05d7c4c0eeccc2bdb29d3378d78c33c9f68aeccd1dcced',
        'fr': '9368f52165c284b6518aebbd60bdfbc4e92fa97aed8479d603d72fb9db12d0b9',
        'ga': '346810344cb58a3110a92cad9bfb5825ac151d87fbd86745b215b2ef41d56168',
        'hr': 'b5cd6ab519a55eabf2fc8e50cd38fa8711a6f97b25063abcaaae1482cfc54429',
        'hu': '02d6ce6bcbe77f5a81a1136c35bb276efd00d0e89ea1240e419ba0a9a8a7a638',
        'it': 'a2167b810f8d993a7cc4ccf68e60941fc3be33862877c1e70e7a8db328a1d9a3',
        'lt': 'e67593f9758e8e80d8bd0b3cde0615af1a4d9d6d4a8336e981bef50301004352',
        'lv': '843b04d5ae1544760479e5a94b32fe86767db4b82cba9e65fbb8551472afac25',
        'mt': 'b07c26f9118ccd7c3a6e964ab9db4f284c19a697000a53726bf7eaa125980a16',
        'nl': '6ae7ecd62f89ca36b80275eb196d00aecc9f82f63f85dcb4c970c0da917e81c7',
        'pl': 'eea9302db4b2f136317af0bc978c4ed4a3b191cc892d3d898f140448c17ef0be',
        'pt': 'dd3fc030a55d572d66004cb10a70da4445660c703dbb6d50bfebf70d81b75562',
        'ro': '09553e5b233f5b303964ae6906b4bf97315783e1d128b136ca532357cb6312e3',
        'sk': '8ac438abceee73f05814ed227f33a84f6f3d099e7753a35bf8d79dff7ca8fb9e',
        'sl': '1c92b4006b35b606efddf33efa86c4b12a15c163b453405d58d4cae8e3b071df',
        'sv': 'f64647cdb411bb8d2bc649fc7e1bf5fc2f89e52860366078c6f174f70dd854a8',
    },
};
