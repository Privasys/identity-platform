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
    version: 'c2bb36ecde948913',
    digests: {
        'bg': '3688e676716febc48271ee1a315f565fe67efa1a4cd555faafd81932a619b25f',
        'cs': 'a598d4dcc39aa632e64c8a3fe691cce7d0b1c7773b255a6f60da12728b4a982f',
        'cy': '9f39fb6299f67d23fe1dfe1ff88a9499684ffa8575f25c76ace71d286a015ec7',
        'da': 'cf6a94176e0869f299ef16ffed598c992f2c9d3b5c0b8e762a6dbe3febc51a33',
        'de': 'f9cd607389c387720dd5e268bce854743289a81e4899202d83d4b4bd56c3ded6',
        'el': '6cfd8eb20a8be0021784fbe6e37c823e511ba75196c7d2b3925d82ddd7f1fc1b',
        'es': '2e115a92c4532dc64b81ea90ffdfb0786c8c6d45dca06f51b571a7b3015a9759',
        'et': '2dfe15d95f7e2078cf7bf23e3066a5c88655d72ec50190af0eed7c9433b0adb1',
        'fi': 'ee5e11f452325f2ce74bc5467ff8c7dfbbf2ef8aa376b3e13b84875ed3be2f9b',
        'fr': 'e72e9ec71c3754b59d1952cd7f1695194264094a2e745b9044b10fb37c8702a0',
        'ga': '575ab64bdc1268ecfade9aa33d43ebb4ae986284c029fed82e663e9fc7d72e63',
        'hr': '59510f4941e41f61631241a2b86b7de7a43e35f4e85b1ccc61c4039b9194e546',
        'hu': '4f1b7f5c9251d5e144c610dacda927cc78ef906ca4662f857f93a0d48034a296',
        'it': '8c56b1ed7da7d4c654b832b33c106b3edad6427120aea4a47e0bc08a5b595866',
        'lt': 'c6eb8663a79df368a66cfd5e2416fabc8f2e8e06dcdea9e81b89ef00b8ff73fb',
        'lv': 'a7fd94d13e304ae9e36494f274a2f597ced8e95d0c77f6d0c8ac604c53c3a48c',
        'mt': '0cd3142bdd09a2391fa6ce19f1248c3e4dbf6acaa167852d278cbcf646a1c061',
        'nl': '566346c6da73afbe2de4edf82b137e08bc731c0c32cddfd1d4803bfcbb6f59d7',
        'pl': '668ab1c376ab699a0665b411ea86ceb2bf17e64686b00c79e616413276b1f7aa',
        'pt': '6aa4daadfb0a0dc7d9eb1a67dc457c3bf66030f9d3d210825301441f2ea9398d',
        'ro': '71cc202c1243c2c1567f4988551d09ba74c4603e7ed5ffcee7b0b12e4b6683a8',
        'sk': '0f8e0f3d240466a0f93e2ba7712a4f9b4ebf5e4fead2dc3ae94ead334bf8d4b1',
        'sl': '37a7043808d128b57681aea6732e3263b09f7103b15c1e8af971abeee1a2cebb',
        'sv': 'f98a80de5e0915ac52ba7d99a1c115ecf29c8b875917107dcb4d47ee7af3f374',
    },
};
