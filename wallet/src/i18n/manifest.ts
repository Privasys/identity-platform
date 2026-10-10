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
    version: '525954112204cdd2',
    digests: {
        'bg': 'f7b6638a3350a91cdd307e3f2d6f12ce2b3c6c98d5dfbcce978317dc84383274',
        'cs': '2e9a3e4d6fc555a08e36244b9f08401f887515bf210e63a12b9cc9c4c0bb1510',
        'cy': '1257c2f5fb6cb44c02f2d7288cd80a777760ee922fcc1d34268a3090dae0d012',
        'da': '2e3d16f55ef8e27529f90eeeecfeba85e6d91cc03b77e5268c766bc8116b6f85',
        'de': '7aae8bc30ac2e9ba9ea2cbc184e7e6097f18ecbc93e5c77ad37635c51127eede',
        'el': '950b927b3481fe39c394f275b23b682cd3dfc8a07d26c585a5383511dd5176fb',
        'es': 'aee7a966fdf806daabd36142ca726fe2a8a5582c614f98869c820ed7356a4a78',
        'et': 'bc2959a6fc1c2cc51604a5c8206a87e67e7cc37c9c353124f91dc0dd61c5173d',
        'fi': '2779da73ef07462db7b753332ce14dfc8fcb5eaca56594103f5456ead02881a0',
        'fr': '3a4e4fdfced2e4f28d67c08c13da2fc05312aff74c2d08e62e17f3e955ed7f45',
        'ga': 'b828f2617f94c79fb00db74ed58d2a613f6142b627221926a119a25de610e0d2',
        'hr': 'eeb72d79cea9ddcb44af483205138deef9716670bee0f3bfa64baca2fb6485ee',
        'hu': 'a095040612ff3262c69a928cd3c9b7bfe316c1bcfc005ffd47558c64866be988',
        'it': 'ce6a4d4a8985555217be7cb91c274741c02fbb06cf6d03d39c94286c77dd7a64',
        'lt': '82e9d996332522a3c1c89bbca6ce1ae772c98ebf16b0d7e23d9389a2a8944deb',
        'lv': '1cd23513602672aa359d88df1d2aa5ca2c0d91950fed951d68dadab774830eeb',
        'mt': '9a2602876ecb65921ace3b81bd7fbb8c13a02f3da6818712cbe17cda6c6b0434',
        'nl': 'd5fbdb458dd84c34ac5fd8198a6d19bd19132e22726cb4326ea2136f57f0aed5',
        'pl': '2899bec4d1e7e938e85ead9e2f97e32367112c33bf659fd2bc4bf9197a3d1317',
        'pt': '1954bad39b57c8aed184222f781d9572b572ce65f8bc38daaac6b3fd2b2a6852',
        'ro': '5435d88fec61373cfcd01990bc5438b91400660bf30c38bf81d1283264fa8b6c',
        'sk': 'e9eea5e6491e49e0648c00f473e2a56f82294163cc1b3ec97f688c9f84cc49df',
        'sl': '678b4800fa597aa83671eae6d6d0f8382a2d6678e1d47f354d32b2284ad1a242',
        'sv': '8e214e39bbc38a7bb304721f832020437bf04426cffdffd4e5a7f285dae7b0c3',
    },
};
