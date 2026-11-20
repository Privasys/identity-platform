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
    version: '69e984915b10a640',
    digests: {
        'bg': '5273333b7daa105249f142d1126ce6e1ec301c7ce90f6e3fccaf86dfeff9201c',
        'cs': '7ddff899ef9348f423b57e69202b0c4d0792438dcf1b9bf99c0382298abc557d',
        'cy': 'ac15d6230d350baa3df854fbb51ee1e7e84958c2c65d9fed96e5f923cbaac34d',
        'da': 'f6f768b1edb8fdc4d84f35eb8480f2439ed64598bdd545a577b02430fdc84e12',
        'de': '9e24651971a17a4e3a8e8c8d1e1f9b7b832ebc0f7ae1934232dc67e622e8d4d1',
        'el': '44ad5ba7dbbf5334d18390c442025489e61aac2d7e9bae1ee481fba3f3437ce3',
        'es': '7c90fdc054e95b55a1fc4a2840f397439852e33c24ee38869ac323e23b7554f5',
        'et': '9eedf9252b88b2bede5c543c26be835feaa6bcf2f32b6248deec9ca6b9e497f6',
        'fi': '7b9561ebe0939e02249b584d4204a6a244df1480f289593a5d1002f8dd135a17',
        'fr': 'c1a33223d32ca2e030e0d51134af3c59d2ef27ad976ead850d5d899402f4ea18',
        'ga': '32d20c7c59f95b5c4b9255fb73cd19cecfd63d9c874cc8f90fae750bdfd4b0ce',
        'hr': '0b7454d72a0a79d67b233cdfb3de0c9de3704faec82bb0e1639a2f32c0764603',
        'hu': 'cf413c10579316953b0ff5bd8e6dddbaad8d8a722d621ff8d48fe4e0446daf96',
        'it': 'd92cd944c0f78f3bdec62c89828fd86e7e76817d0153f80481eead44ed2cf73b',
        'lt': 'c10021db25c0c000b1391546b5171a6c67dc311f886682a9fd61f0fcf8cb12f7',
        'lv': 'aaa7f8119a59d22f79468fc3f356138651bef96804f9077b63c6e84aacbd1af0',
        'mt': 'd2067254ea4d02e0ccdff45017b4b7c358bbd584e4c56d0f178e1ade08fabace',
        'nl': '3c0ee90f7187aec81bfcd93fed39673cbb93c6f08f0201e0c9bce0187cf8b2b0',
        'pl': '6dd6fba0215c6914a3409257f665a7215ccc2514fc902f9467aac951e4c5c6be',
        'pt': '4186986eba6b7052a6ff79d1c4f511a74ec4857718791b35fe7b8e52315f686a',
        'ro': '9bc55087f79d244dfd3312ee7e439edf3e04d399d29e35fda45ecc576509ce7e',
        'sk': 'ae9a6fd068f6edd23ede4b476832a018429651736ae7f339cb29b8e0827360d5',
        'sl': 'b14b4689e489a3b3352d7ea39d124a5b36706cb9b16cad03f677e39301da9e85',
        'sv': 'abab34ecc351fb62acba8badd81ff8dc476e76d1170685ccd507a2f1632a62ab',
    },
};
