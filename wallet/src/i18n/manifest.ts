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
    version: '87af556ba7602610',
    digests: {
        'bg': '288028219c2223ddefda4f4eef279cbe22c7810a52fe941973cf2bd7cb353f65',
        'cs': '2684bd2c98b79070fa01eb00d80d352490b5226bc2f9b1f0806c2f9325c7afce',
        'cy': 'b010aefc72c5fbad38cc77491880862db20efd957587f44f31c59eca707a0ad6',
        'da': '1183cd169d010e92d2d81cf8825a8a6ecdc50a7090bdd59a907885cf76651729',
        'de': '3ab13dcf4233642b6c2a51b6611d281036766efbd319f56610ff57b99e539543',
        'el': 'e77ca0a5458a71d2171df35ccda1b91264111504a51df8b2a42e2e3ba97897d4',
        'es': 'fdcdbe6834ca61212f310d3a9ce995b5b663f14cf01e5e307affabd990097d65',
        'et': '0fa50abacb39657b01f716d5c5759281104a40195dc252a2f7cb642f74d4bd5c',
        'fi': '82424b44c66039511176618eed68ac2b9a2fe09232f2ce287ba69ef84385f8a9',
        'fr': 'f6ab376ee08cd787b89453cefd17860ac21acf5eb2a220cadee90409164fb3a8',
        'ga': 'c9fa1299d8381dbaeb7d1572d908df3154b0da67af8d1436b3b5865eb4180144',
        'hr': '37400e99d1f4376a13465cc1cda47e2b50e96dfd593968bbf34b628052b6de97',
        'hu': 'fd999dd08da0706eefb2e46ed574c13e0f0ab081489bffaec50a8898da9d918c',
        'it': 'ae84257287fac7e3a258472240bc5ad304454549e99c00e94396f1786a69608c',
        'lt': 'fbced8cef04387db77b5a66726cffe82c65cf07280d567ae616ca4f47fc9f8a2',
        'lv': 'bba6603e4c52e30e3ecd2c97944e3e8cc5a235e383ae7e0eca6a289df1cbff54',
        'mt': 'b08392e58f55fac9a28ac0feecb403a783ef238bf5177275f54e6f72b73b018c',
        'nl': '408bf41d512b92645e88a2941986d67f191069905f64cde853e1ded76ee97931',
        'pl': '378bcf94c5a8fe3a8d6b8a6fbd20d6be90732125d70a883f1ebb7006d3fcd182',
        'pt': 'b299b3075cbdae5702e34caf5c628cb78d4d620d78e60db17ce68a3150183e86',
        'ro': 'd79d052dae7b465c5d1ac472dfb0e06967a0db7dbe8afdc5b928f3d830340e97',
        'sk': '3dd74d33047b1c190e57301bea6df39d1b8220860b8a0cc0e80e4696e9743017',
        'sl': '5d17edbe31a2eb533e169b40e4b56a8188fc82e99892110a6f51906044342290',
        'sv': '7763a1b0b8e73695df3841a394877088b15a2535f43def7a2911de9b59e52d98',
    },
};
