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
    version: '7c2456c47727e4cd',
    digests: {
        'bg': '4393f7d8077ee699c56865a25ca4aea2d9e4d33f9f05a33a64f6d1dd309e0e7e',
        'cs': '61f41f0a9505287390c0c41a496f145a9a220fb06730921148e3b349b040f23c',
        'cy': '1a1b67e777206d74de7113d44a53721799e793420eb00256b0d9f3e2f2aa0874',
        'da': 'a844505549906fabc7d655483af25a560e30e4bbdd47ca2c2a92ad105bfd9dc1',
        'de': '90618b96c71bd229590834f8fbaa08e2679e9054a8fd396ce84ded5c9b1e6878',
        'el': '3dd924e2f0ef142010ab9097853e1379f4196db8c870c266ba548af333ac6bf9',
        'es': '1dea7140a153754044ab8f4fd3a2c447284f145d8b0e18067a8f96bb4bfc8510',
        'et': 'e79e7df3ca5d3b2ba2dfa196e52cab7026d6f815bd6d1504da66ae6a05495ebc',
        'fi': '1ec049e3bb26c8a212969d153b6a4e7e10c912359f688460e6f7cfba45f86d89',
        'fr': '1d1ca5dc6adb8e2277a66832ec58e1b2335712229b103148e57f79d5549191ac',
        'ga': 'b43d8d262891328c6ad94c9b32848d1a7a4691bc001fd50992a9abaf2a67e42c',
        'hr': '752bc58395b4f4f58f5429f91bcde39e59f4840ae2d36db25969c476021d1a28',
        'hu': '344c49f657bdaf6375f871590963a277e4a31161f8f0848077eadd4f75991ca8',
        'it': 'd71d3248d0569c55eab9cd1b3eebede589fec6a81795277e5b289f8c24e563d6',
        'lt': '2e8e78ddb099a2f5fa25f55053ece90f815cb1b657a76568aae06dcb285127ba',
        'lv': '19f028353bc88c47b034c58c5f1847aec0303d04322a6f7d12c987fce52336f1',
        'mt': '9046e77c8302ca921f63f439d94a61a37ad855c910bc988bdd2c1ccaca276766',
        'nl': '38c29c6ed6ebaaa2071edcb7fbcdfd5d6d11e0ec3781c53c27fe4c796bab5d2a',
        'pl': 'b7bebc8fc913b0710ab910196a3ebfb90b091848c782fa36eef8890d95d05064',
        'pt': '1215adca6da86eae05a16f3c1428298208ac657b867c43f3efe09c4d24dc1f3d',
        'ro': '1a866739dc22f04e02a117acd945845a8024039f000d99d9f501e7e411ba7d08',
        'sk': '7f07468288cc610d18878e7761aa8fcf28c2891351409d6822fd0fbf40b3b2b6',
        'sl': 'a47e25527ccf1e97cf678b16d2f909ec6ede9df9d61c6eea45ab51da8837854a',
        'sv': '8c7f16ed2fdcee21f0a5db70fe6a66cb9e085bae55aad467fc9fd9fdf62b679c',
    },
};
