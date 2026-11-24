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
    version: 'c7e2226d09011e7f',
    digests: {
        'bg': 'fe9fcb61417492ab0bf78e591da4094725a0e746c38afdffae65a86fbeaa1d21',
        'cs': 'c0d73fde0f4a9bf5a1c9325b6c93d159d4a45595f5cffa49ab1d9a6567853398',
        'cy': '5c20f435571897c76ac59107cd7f0238d1a9e3447d88ebad98b57a9081e8f332',
        'da': 'c01f56fd8367fb6ad5456c5815ffd7533421710159e2e438d671829ef21baee8',
        'de': '3df7c08d21b75f6a1d0d2a09c6b50eabaff7e845d12a30858b5aedeae2de38e3',
        'el': 'ad3aff0ba7db037197ed480bc81856399391ebcbb0786f1d5c8c9502dc077ba1',
        'es': '56db0f0e6821e27d3dcccfb8cab309e8eb423c8e934970c29cef2cb8c91ec486',
        'et': '66a4618fe3426ac5244dc1e670e87434dd556f71f191b3f9198b91833e055182',
        'fi': 'c733bc14b285b22793f9b77589f1f7b3ff8fc4bcfb9f5d7e66ea9fe922247b68',
        'fr': '016571799c978f766091e1f43217b0f6d07e3253a8773c80534d173d784d03c0',
        'ga': '54eb7b97dbda1c9636efa300cb1e9165f4b3575b98516f0a85ec9acd8798c4b2',
        'hr': '3004569bd96dca005457df7e28764028bfb248f4395d3aa531c524da679459fd',
        'hu': 'fb15681b395ef07d7d7ff95480780bc1c212766b6b618fe30f0f2f6e79dd31fd',
        'it': '7b81770a29191b28d27a4c7d235ba95440495c2a71709e393e46a728739221cd',
        'lt': 'b954337652824a0975ddb9ca033133122ff704b31c44868ae70dbb094e111e71',
        'lv': '63c9709ba6e5d99e8295a52ccb934302ce42feecdc4b9cbd7ce8929b0e49354a',
        'mt': '2a42caadf8f3eb911740e0e8d6aed9a4b784e310721c18d3c4c74af42cb4fa61',
        'nl': '076e5ce962da55cc90f4f0d167d42989028a898dd0f45ee0bea7144854cbad59',
        'pl': '42332afe8dc2576d8225d94e8ace5a8b88c7f252731af9fd415d56e1912f5177',
        'pt': 'ff05657797c64ca37c8e6d11e6b32200a212240bd40bea562abcb50008f328bf',
        'ro': '20b2864c1ca5e5521a357c73fe7bca87915dbc6547c90e93d4cd71b31e4d67de',
        'sk': 'a249c3d02b431c51e651a39d6f0a4d0de3cd13ff12cd3ea5ee503efcb99e1678',
        'sl': '18409b7499579be81a7a8f740a936ee44f19bf00e56499dd0a89f1b20ad68aaf',
        'sv': '194212849aae767a5f4e14fddd63d5f3c6eea65e0fd584e40fb5dab97d841ea9',
    },
};
