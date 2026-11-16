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
    version: '2e2b76935cce57e6',
    digests: {
        'bg': 'a38b45dbd65eb7b25f662c56d8c2a68e3321a871a67f99ff88920f5bf9116143',
        'cs': '826bc1d86a06b13b21e31f05e3f80d9694387fff27819cea67d2b61b4c4408d9',
        'cy': '198294de527f66b6a04be6c0626ed6c393ca4db898ac0acd4602f5724af5429a',
        'da': '7c880d74c2c2d9da0e8aaf525e1911ca5ae15d27dbabe48de0b05e2d5212f27d',
        'de': 'b41369c6e57af468201e9cb35e9877c3daa8064c27ad27d91268e79df55b50fc',
        'el': '9ba124249ba52d05ab351a786d291032d10412bab18bce8283e92f8e0b4ffb36',
        'es': '969cd01cc1ed603c8c2335c62d466028fab14f318c48bff128977dddf9b4e74a',
        'et': 'a291ab35d024a9340dfbc78918d21f7c1d8e6317a8c55d3c46092465398d18a3',
        'fi': '0cba83ba41ba3206fd216c13ade54b7c70eb51fd90ec5e44581b82c3f2f92810',
        'fr': '5f17f689503d02d1e2093e19af06c48890fcabed6ae142d9c2d7162d75c377f8',
        'ga': 'cfdb70f27fad957a60d248e877a3c1dfaad68a5d292e84354113cc0134f477e7',
        'hr': 'e7c26659f5c3d8febb63d7b38e1f508fb7b4872e2b48a4891eaf8aaad155b8d0',
        'hu': 'b9dc71924cea048543638441e14ba3edc2ccffdf8bc82ca7a13e651b5dc522bc',
        'it': '9f7f4b70002e35573a0b029f8c6bb55a43949452ed8fb0c44d16fcd0bc6fa111',
        'lt': '65f0ac136ce09aedfe4ce0deb4549baf392e29dfcb5e6382c034cc9c3edb9dc7',
        'lv': 'ee2fee6d5a8904c854e85eeb34cc0d98dbb4fc522054c22156df6ba279cc57a4',
        'mt': 'bdd9dddf2d2c4fc149f3f61dfd4cc82e4721c22f63bef83e9ce15afda51eff66',
        'nl': '1728539a6bbf8850e84f1f0a6a4196148e019b5ac5cc0f3797219c53ed7cfc8d',
        'pl': 'ad2cf8999b50df3ac6fb5f65b9284ffe38fe4bd2c39f20f4c00e8222b4f8d09f',
        'pt': 'b87e571b7fe8333914601f0d7428b4b447332f65c00b7734839520a02df27a5e',
        'ro': '1fca6a045a4c504f5b719406818400873e9fca84ee77a43314e3385b4cd179c0',
        'sk': 'f398778905f64e0a96bf73a6a8fa44be7b56246a7bf7ecac21ceec3eb8403f4a',
        'sl': '3f4b81d8eb38130a45f60d6321602a24a33782e9f5d2755da2e4b08e91fac755',
        'sv': 'd27a8945e856332b63eaa8bfa266476da27e44ced9b8f1eeacd7e7fb5d5f6736',
    },
};
