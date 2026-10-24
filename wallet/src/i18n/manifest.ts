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
    version: '55ca54de25cf8ee9',
    digests: {
        'bg': '9b082e01baf962eb232864b3e8e9611102a71ab39dcfa72777c0717bc77ad21f',
        'cs': 'c6a815234fc04811bd509bcbab4dddb253ef6cead96daa41d56b7a60298ef379',
        'cy': '8e4e5a5acc1af25a63583f50a4043146bc7a1cf991264c55378428282529cf33',
        'da': '7ae17231dd503172473f9dced86be6a917633b2e02fd57475fce004b32b1fada',
        'de': '6a3375cc23eb1a1e683806ec8467a5c82a92300140482ceebb00a1793361f21f',
        'el': 'cd71ed12372508a4954eb8e284bac2671b04f54cbbabcb6e9876b003cd6a703b',
        'es': '3d64d3e2cbfd23538c1fa4cec5fa7e58610ddfc7a0f10eb9e6a323eac80882bb',
        'et': '9530571907bb380ffd772ded30545a091e983ffd6940d2e04879e14454c37a88',
        'fi': '36bc55d0ec1b0536aababa979abb3637b0c7842aec9d7ee94765b9a527c27616',
        'fr': '4250edd8f42b32b593dbd7e182e7d121d183d88f21b71f87ded7e43bc363357e',
        'ga': 'b9ed842ad153d0c23d5dc38fb17aa8d44b6cea915912150141a89961d4f1662d',
        'hr': 'fdd5aa8d749ee803b72bf43b8a6801111660354ceaa50319a8a8f5a46e5d90e5',
        'hu': '618a1455cbeacd32a7d7d7c5ce7492e3664b58c820bd5ac5ab34b2eedf3b0e26',
        'it': '089352b20d742e8013ef165cc6f45800abe9297aae0c80bc758a758128ddaf33',
        'lt': '078656cae5dbbaafde11b2aa8ee242368cedb131f49d5524d289c0b8967956e0',
        'lv': '6c5b20f882d1bfb1abaeafe9ccee800997d48bb73faa9242c9618ca697fa6372',
        'mt': '7c1224b1e5ff863fb16716566a7cac5a9b25f0d3527c4c1f12fcbba2587ce50c',
        'nl': 'ec62ea9be8d4394052b831d7f2174cbc216989cf0907a90ba43e4086c422ee31',
        'pl': '80b449a7bc3b5ee6830beaa132b900d9db6d7ee30aeb84abf6fb47a52bd6192a',
        'pt': '578dc3d023dc18cbd7fe5afb2dc77d0d4ecb1262b8b8e6a30702b84fce8f50a0',
        'ro': 'cb12ded19acb1b1fcfc68825ace54b9bf0f45248d9002992cf9eca998612e3dd',
        'sk': 'f4dda9c71eadaf72895e33887fc4de1903259bbbe78e06fd310fea3b0a41348f',
        'sl': 'f87bc4b5def3b5e8efa9bdebf9129a998cb251bba287595bfb59ab8821636eb8',
        'sv': '2af43816c58ef852ff6b225471c4cf8e5999a2975f5e5f946297a12788a3b75a',
    },
};
