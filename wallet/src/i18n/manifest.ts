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
    version: 'b2b89697556cca92',
    digests: {
        'bg': '82a64136d466c1cf587522b6c6307b37adc2c19f53a87fa454c079ce5720f0bf',
        'cs': 'fb84a78f6a282924a08db6597e19cf0d3afb0d3b05b686aae794e5331ea8b412',
        'cy': 'e0cf2db0ef706b4ee34dbeb07dfd0c68a19e0baea6fbcb1dcca5852e356096d1',
        'da': 'c45399e7dc765293f76edca6b8168a3d80759913fb0e2b77323ec57a0de54cec',
        'de': '96ec8bf129ac963c566c14d68a1050a9d345fe06c76eb7721ffb0c971e093134',
        'el': '93f89a0383671e19044cdb1d1b937149732705d1d5f2910f2a32afd36d794909',
        'es': 'a54ca6634fd9c490ce6f24de69ba4f0c0c28b5d66e7a37df21a9b518eb884439',
        'et': 'aaecc5c5baf3cd5dc8910dfd62f248c57aafaf31873782699fe8178e9515a750',
        'fi': '0f15bb82660d5f5418d9b812196d2d9c5cf4ea61eae7eba2aa411fb8c5bc05e3',
        'fr': '2a17b9fa008d65b70d6c60f86a0d22de4bc9715511897a83adafdaf742eb623f',
        'ga': 'a5c3f4ffb9cb56c180ca4a91fa7c88669e70d85b3ee8ac302d5862aaff0115cd',
        'hr': 'eb895a155ac535a95c2a93d31c53c5b6ab32c2ecd9fb6eaeff32acb23dd23752',
        'hu': 'a5e819e97f5ca1919d46fb3bc7695eb560ed885d8c77fc721ca952063e06f77c',
        'it': '386908e7c4843cc3880dddd9666271d01c4539ec31a9548975cab519f9ac2c4c',
        'lt': 'a52bde0e3b6636019b7aca2d166aff37e2b50c98a5a976523de721f2ffe4fb28',
        'lv': 'cbeb59f71eb860c3b5956fb85e2e46673bcef165099687b210aadda8e9a332b1',
        'mt': 'e75d5c8d6b38139b54f943a93431d29d2259d9ae9c0ed7c8a48c63fdbb5aa9cb',
        'nl': 'b353278e321d8147e3827ec6c63a892ed8a8b0c3cee5f7064ea8a4cd6f2eb7ff',
        'pl': 'feda5e0952d426baef8652473255368ff7f71661ebd60486a5f9a96f9d3ef75e',
        'pt': 'b87b9ffcd9d2fb614f46706d4fb14fc27f31adc3796cbb16b00efa5e32ab6b52',
        'ro': 'd16479bbacc1dc94e39b6404fd4e485d1d361ab246df64c2a1693bb867829179',
        'sk': '9df7db541463ae628d386991af8246b8deb7b468ce16919516625d3064f58127',
        'sl': '645e72b973114f4652939ecc13e26c298d93d5ab5df5cf88d84ff9280295fac1',
        'sv': '4552ed0924883993c63c3508abf1a65fc8d81b86c5aed1d36ea067cd0b3d290b',
    },
};
