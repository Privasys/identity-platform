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
    version: '6041239562a2524a',
    digests: {
        'bg': '5a16a4b33bb62d3c903518d86b82710a7a10b52e7d2f56665fdb85b2b59ffcdf',
        'cs': 'a9db8c9ec36f949f029366a747118dc5bc345fefa0ff16c61d5369bf6e21d18b',
        'cy': '96c7a435ef720a4ae09ae4559e4c49b5f9fc1a9cd9693a5ea309c1bdea3f14f2',
        'da': 'e98820dd33d1aebb6308955b19c6d6d8941c49c322422b704bd0df19be4c98fd',
        'de': 'f44775fb35356e702bb712fa9c5b5e1453f2b0e2d263281be9977e5b0e0793f9',
        'el': 'ad48997e269c69769a50f5a0b6e4ebbf930cb630a99bdc8f3e7f89a0e8bb8b0f',
        'es': 'c99986b6de2462c703856ca608a69f55865fdaec65a2b0e434923d6dbf820164',
        'et': 'affa7dc76473bba88c8d116d187dc89f3f74fa2fbe1f834eebb9261c81659704',
        'fi': '1e29e75a874ff04c0c988f564a60bb8385d01bcd091ffd83ca2617becf4281bd',
        'fr': 'f87a79148eafcb62e7661b854e93a58ff819c3439db12b1203a93103eeba0881',
        'ga': '39d9d15ee582c95d5e80b87476f71762f14affebd0264d9e91847a649472cc91',
        'hr': 'fde288d86efc9bd9d5cdecbe7addb79064b771a4a3211af6e15166e6af94bace',
        'hu': '0546154161cd254f022dd416521a84c6e19db9b111fd9db05a6d3f0dc49ac8e6',
        'it': 'cc726b52a9bffb762d421649d25aeacd88600f76d512e341cb5bb5affe648893',
        'lt': '3d6a8daad27682a240d3d00ab4b21852532e27c6e64db851fdf5e42f2068bf6e',
        'lv': '712fde358b862dee9d2ddaee700169287f8ec2454a91c08ca77d4befa66600d2',
        'mt': '6534399142ff2360b17fcf6151776cb6230f3a272a5c7602ff15c7ca199d7926',
        'nl': 'db50d4a3fee0b696567b29c6aa6abebae980daef7347ed2486c3888496025a6c',
        'pl': 'd52d162f99813d1c531cd31b03307893fddd78647dde053a1aeeefdcfc63be34',
        'pt': '02bbd35536413ed9ce4ae0726c04f7156e867b19312bf396b081e5af23f78048',
        'ro': 'df2ccee79cdbdd42f6f73b545f520ac13f040252ae4d16725ba5ce16a73705ac',
        'sk': '4e622156369163cb85e5d94e957d21112cfd7a395e45513eeb7da00831d31b4a',
        'sl': '014edfbd8eccf04da3a722541414979552a773c03200f1f6af7b30fc1f17496d',
        'sv': '3b789989a35fd98ed307fa10e3660465603b5b3ac08c2b720240d0b35b1263dd',
    },
};
