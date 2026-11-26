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
    version: '8171a01c318c43f7',
    digests: {
        'bg': '67169f1dcc7d5ce2760036357b9d0226286eb9927a01f31c8703ec9235c07062',
        'cs': 'ec5c765bac03ff3a33487c9e365daebc64dbff149b1562d30fad5d01f937876d',
        'cy': '6a5929aff0b5c37bbb1973a1d86e40d64724c61f2921ef1644f1d1730169f147',
        'da': '9b37eeca5fcb334d964e55bde88c1c73a0190751f8653ad1c6634627dee1c78a',
        'de': 'd82a1ca584b6ba4e10dd29314dff5d7ab372d0a99613f49c0a9ae8da1bded5f4',
        'el': '0a1398c7da12dc966407fe4612a9711f15f0ecade171875d7053c49a03b90bc7',
        'es': '71e9f9f29469b8a4a95fe3dc3e1b37e04a37a5aaa276f9c50263f447c5e849ef',
        'et': 'f0128a696cf06f997406c185e3afbf9b8e50ff9f49f138497786039364f55033',
        'fi': 'd01a951684e4503682e4c010865b9dc89991a5d5dd8d71fcc3805764c02ebf09',
        'fr': 'b7943d8792a18fa49c3062ef1ea02346259009552b155038f381227345ae365b',
        'ga': '8ffd4de2bc17793b3dec2ecd580382e7f23a6371731cf4ef7172faea093c7c43',
        'hr': '98f2b639239b96a7d94340279610f41f2056ad90becc6a042cf467bebe044532',
        'hu': '63d1f2b1e0d26f9aa84edea7d479bda4d9e1d663b289c4fab1a3a134960d6b0b',
        'it': 'fcb19163449a1cc20d8464678809f87b01604fedc0b38ca50c2a1a53129c6f4e',
        'lt': 'f68acd965223943864ee43b50cb2806dbede54d589a6f1be118235ce43bbebee',
        'lv': '850c110fb5e2d11837a70195d99845d0f5eb4a9748b31e6f87ed274082e10645',
        'mt': 'f912bcc42fe2fdda77fa46d442279331fd1c35a16e1dd3c1305cd31687ad1de8',
        'nl': '64758b626feb53ea47a4a6f0bb48bc5e84a5a8c54aa2bad186844c263dc6df33',
        'pl': '163e90065d6a979cac4145ed7689fffe8fb6d22ea86c8eab3a2bbf3629c404c8',
        'pt': 'ebe6a79b2eaa9a428416587cb1bf4d57bae1b0b4c0e50eaa82f15e12432a761f',
        'ro': '54232fa3557ef8ab0b7f55918600bdf269a48f3eebba979d5403ec921fc9c839',
        'sk': '0a374fede078fd014b2d9b506e636de008c48f423f1c1aa73556d2918d900240',
        'sl': '0618fb0a359640722cf89aea0ddadbe2adfa363b38ab654e9d318e247b09b892',
        'sv': 'ecb2737841787b5debe617f92048ed01a541df58fc7e0b7d14eec45c880a6154',
    },
};
