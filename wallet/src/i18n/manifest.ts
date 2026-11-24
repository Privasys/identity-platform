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
    version: '37e369e32cf8126f',
    digests: {
        'bg': '071adfd2d750fbd84be12ac3e2a0473ba3be78b8f0acf701fa5ee0c105dfbf14',
        'cs': '8911c57d6f06b790d76b344c823a61b7f03ec0e6e4be776fe8eab629b2d39d63',
        'cy': '46ca7ec16f25aaea13e759080a24a61cca671c0df48134724e86542d4b3a7e8c',
        'da': '443f4008246a9c02a9b26d0d853d644059db27f23af0d701108d7b0bdcb030fe',
        'de': '755e2e6090e4b5d68bdb05ae2be48ae25e9f2fca3428be717b67a35b880f1f15',
        'el': '4c3baa4d2284276d183088f98c719af8649701058b4497be8fb975b1ec992c67',
        'es': 'fd9208a8ec9bef3a2672f5f4025e36e5cd5cdbcd4a9a689b498532eb7ce08f74',
        'et': '48086806b51cd2fb37a4eee7b7adf34be59543b2595b1545cda550ac88c81100',
        'fi': '56efcc8f2f1cdfb0db254ac4b58f6d9fdbda3ac7e2b3178d298db9e51a386405',
        'fr': 'c9522c7975164ffe1c11d55182b12ee95fc684e47fee2d172ba6d4057841fb2e',
        'ga': 'f4aac40310db15e6dccf898fd026eeef001e261b9fd4582ef393cd24650e2f6a',
        'hr': '69759110061451ac0f0a1792253397d3966e59163922965ada178b30606c90ae',
        'hu': '4ac7bd9a8f802eb96cdba3b1609422dd740e6af3d9eeccb503100356e8f20257',
        'it': 'fe14f3a7b272cdcd789680074d0fea4df191722c502317a3ba90908ec9b34a5f',
        'lt': '4188146a405ced4ac7c05621396eca3b17c768d2d30f83e1b563e88e53537d0b',
        'lv': '9e8182937ee77113bebc1cea5440c20c71b637a5597a40e5c34717f9f0d8aafe',
        'mt': 'f16cb8b8e7a89516cda5ab5a9692f5c5ac8d8c50e7f93bc7da13feb4f10d2c54',
        'nl': '1b9da86dc710bb02afc277d4423f776b8774241ed8029b090725ce1c26e01734',
        'pl': 'ce3df1275965bf69fbf824cd13a67ca7bd3b81c3775bc5633b1fdca296954006',
        'pt': 'f7c9898500eba739d0916b69d32e93a77842925757f711ab676d5d8de11d7a65',
        'ro': '1f02552770be3648d4ed1672aaba886c7908520b5c733c66fb7ad823641fa4b6',
        'sk': 'eacd7efd3edb33daddaee3abf31ea159162632ac7f8c5e4d09eefea1987d3f78',
        'sl': '6a8e624ca0d05cf521c20c952863b9b70882144c419b392f657d47c46e928b70',
        'sv': '7fa0943cd4de8d07966cfb388bcb29ce4bc99f4ab7462b0f362e49ed8c189949',
    },
};
