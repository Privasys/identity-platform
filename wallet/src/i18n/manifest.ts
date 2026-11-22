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
    version: 'c8b02e94485c3e12',
    digests: {
        'bg': 'ec802211feab4f1c485218761ec4fc8aa6b4341c30549d2067252184294c43b7',
        'cs': '552a9ff0cb2e2fcfc6ecdf28241192047fa78d32bbdcadcdeb25882311f3abd7',
        'cy': '441a43bd05fb8bd98ddbbf9731f5c202f80cb47a2b3c81def44c581577227f94',
        'da': '5de2910e49816afc3487f321a75feb8cee524937ae6cecb36090b34fb26278c7',
        'de': 'bb2f97d8db6d348d7cd33e3b1ae38fef1fc8c7f6e7783043a46ea763f8758c2d',
        'el': '8e7ac39d653907e69663ca75a7eb02c006e564d96ac1e9366b831a170cc5aab7',
        'es': 'cdf5995779e1618bee23d1c80e1ae212b1f024acc0f24d001c6df851c7d0ac5f',
        'et': 'a9b5a4e9c893155de6247eeaf5c23b9ad06faea6a11a3e527ad0afb6291c3dd9',
        'fi': '4591aed775efff3e794b34b6424ce4c35310a1d4f204a5295ad5824d43bb3b1d',
        'fr': 'ab49276fab243f56583ad5e55e09aa4d4d696ac1ad01e2632b91e7059d4ef484',
        'ga': 'ff99fe9e1ec13b2877426ff0c59e78e8cf86464f664a1ef292b670196d2fc18f',
        'hr': 'c5b3253ecb8c32d4671fcb48e7f1794a1268e564a8de2c72547185fc0f5f5ed5',
        'hu': 'aced45739742ebe8e416899073c4e1f6549d9067ba731bdac0ca1184da9813a8',
        'it': '4d86bd98f71d4988d4d8589532eb627784a75a3fa23bb50c9612b58b4b4457a8',
        'lt': 'd85dfc453935aed57a46d4cfdac57bff941e16beea870ac41efd6ea048ff3c12',
        'lv': 'aaca352b8d0807727bf8589db5c2fe5cb79cc2b0ffed45d45a3daef8cf937bc5',
        'mt': '654485635ca3d44ca750acbaf1c0e2d175452b8b0fcbf90e1730f431dc56c736',
        'nl': '596d94b5d39ba06e1381c9ca68200b48f11a2a0974f326df4ece13c6f0d0dd1a',
        'pl': '420674b20f73b004c94523a56fe7e9279bd51ff67a90b2bf00e416f005ed2798',
        'pt': '833503d5098360a1ce41c1e60d9926b7c4e57a08fb0d86f0a1be1325e354db30',
        'ro': '44d813f79773ecb2c7676a5ac5506d0b92b61618f1db9cdba2d1e7b43a14c249',
        'sk': 'b706a221bb7d7c62899b9b730c6cf4b01ccc789a22a78e483bc187732a370831',
        'sl': '6a7184d81a2c0a6338498bdf80b86d9110d0f2028bd1e03160b81fe8e9a19cba',
        'sv': '34b9746427684b0f796bcf54ff71c1d3588be70ec268fb886a34cc4877de60e3',
    },
};
