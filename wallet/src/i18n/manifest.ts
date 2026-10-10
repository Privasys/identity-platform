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
    version: '61c6872e51cf2f05',
    digests: {
        'bg': 'c3dea8dabab53d1a1c68db4dc491394dcde9e61a9532ab27b67ee489f166fccd',
        'cs': '1118aafb763b7a6f4e39612de35ae3dee948eca926e4a67fa3e12ef501cb6aa5',
        'cy': '628758a802d991b9d9129d33cadca26d2babe6437ac960ddc05a0c47699917dc',
        'da': 'ac1c5f22dadde4a020b074f0d7eb9ca5e798fe5187f6ce251c68c01f6580b2b1',
        'de': '50dcbf82f688ebd4f5b1ce161e13e6cdba17ab39c582fc3de3af97e8dfc49b99',
        'el': '43d355eb70b1d489649729f0520b436d108e62ef86404da3771d6da4a7b3bbcc',
        'es': '9c4a0e8d064f656190e326b11c4932a8192a18046fbd62c5c273034599a5aadf',
        'et': '581abd11cd1a0aff4dae43d624da668c4a753c28640ea02a86bc577a3408feca',
        'fi': '7005aab591471c68eb319882e770f117ea1282506a5e59566c07f2ac0d6986f1',
        'fr': '05be40d7c95453964f8f895438677ad823fa0d9accc720838e1dbadd350a40df',
        'ga': '6a6a07662f1151517f38fb9807026a6de48e651237f061fe669043b62d143f2a',
        'hr': '07b5d7c25dab019d955e69189a73591dae29bc3df54e29b39b0406ac775f57fe',
        'hu': 'fe608e7b0dee6e14b3c0d04ef79b559f806e6ea93c3583443d7e636fab191add',
        'it': '3af7886b5e5d9862aeace4f242a9fa2065d15efc6994c2324340358c18fa9c6b',
        'lt': 'ebe077e6d94b55603ffbb0e88397b54c6b00e86c23ae49bd327a34d9b7b60fd5',
        'lv': 'a48fed54bc84b4f30b4d6bc32e70490cefc6bfb996ef151c2419b2746b78c6b2',
        'mt': 'a9e6a1864e4a22bc444a7ac100e385cfbec5a1e476c7cc1c717471fbd2db8d54',
        'nl': 'ba6f57f6d2eae8976a3637785152fa38fbd48bb8d404898521a415d0550c9a9a',
        'pl': '3c81cfadaa8dd04c02ef7b1ac11201c0dc2f4a21374387a8ec21c47554dcee8c',
        'pt': 'ca6bdd3818f1055e966082ad2151954460d5f0d3fa47a4935a3650e2fb3ac302',
        'ro': '4778d689b833a6de086dfe085e0194716d73d51fdcbddce85abd6ebd22c07e10',
        'sk': '28fc371ffe523eebe95a75899861a56170958cf689b7178a327120305d90b24b',
        'sl': 'a9495127f78e4acb237ac6562c2682d7b5a9705ac5aaf08955098fd96b17360b',
        'sv': '412deefce781a3b654e284987857c67a7fd732b5f9d5c3a35c9dc15fdef7f872',
    },
};
