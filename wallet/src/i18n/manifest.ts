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
    version: '9cbba002ac880175',
    digests: {
        'bg': 'd43f73e60f08ea30bad446c1b6af31a50d2a5f03b68004a6d7a5daa65b930a3f',
        'cs': 'bc8e1103ca909cc813ea2cdad5494f224237f38db4ef17bedc8c39323c8c85a7',
        'cy': '77c7ba51434540e844db88a28a26f7f2a1b89706ac22db40b38e0354ea9a4cdd',
        'da': 'c223b3c4b4148fe65f87e6ef9e0fc35eefc2ca6c5132a330a0b20f6095d784cb',
        'de': '877cc619ed6962680b824877d7d5d61688e5cb23b29801401a5cbc06e8ef4e89',
        'el': '3595604e5754fc550ca8de8fa61be25a1e392bc042bf4dcb99a6499e9e628505',
        'es': '41428c28e0af1af679b8e8a68cd99c832d4448784af35b05cbf11d5dc2ea48c1',
        'et': 'f60577997b56dab70bb0c912bbace129ff70cbc99701fe6471bd1e25c132a1b0',
        'fi': '5b53b24a751fea8c465a45d81ff9d4cf69af6bd7d241cc4b1281ee57b2ac7da4',
        'fr': '2a69f6ca03c0a49129b120e77535889bbffdaa95f62233ffc47852fda120687b',
        'ga': '7ed797303057b55687f1c617014b7df86e6922b11b208f2b139fa3d05a887930',
        'hr': 'ccf2e59eb4adeb14f37662ef79f17291c80a50231fd000ef3f26a3d0bed2879e',
        'hu': '253623e7bd82122ebbc4dbadb69f642dac8a544b6e5126387f2a3e7442db2d90',
        'it': '6369e709e6b003f6ea755e5f90b9634630b6dbc50d61de01c214960760895e72',
        'lt': 'cab5dcb5475492ee72f4a9b32c8d3e9ea440cbf0b308dd0e184a39a02556c84e',
        'lv': '78f02595acad7fc3efb4792e7006d5978f4961ae65afbe781e666161e718f9ce',
        'mt': '24410b1710bdcc4309d829c259ddeef29b8b71ebf3d20275eae6d464e0e76162',
        'nl': 'b7ee8efd01917616e5ad31efc024fe2e63605bdb23cb76fce0b58a7482ebe07d',
        'pl': 'd545633a293b907693ccd6057d742ce19c91c556af78becf3c68f1e6acee5603',
        'pt': '5c9fc7f6916d1bbcc11f672ff996cdb0cae73b3a3e9b46382b6880f01d1f5348',
        'ro': '6dd4d4067717e489a72f7bb10e9882b82f54b4a71a636312881ed8c1c1e12359',
        'sk': '11ae71ad0486eefee15574626b34b2e2795665ce5748683c9a2d3f36dd6df77d',
        'sl': '16959a9a88797ac944ec174e7ebeae3be8ff302ad7c937e3d9fb3576cae414ab',
        'sv': '5dcf82102ce5a8a63952b0ce386d3befb1d00f671914c319d47932990ee386c3',
    },
};
