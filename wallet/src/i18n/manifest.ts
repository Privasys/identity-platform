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
    version: '766c2915f4de651c',
    digests: {
        'bg': 'ef059ae364d788763ce03f171bf02a43b464b5bd24d30c4e413db07c2bb3ed4f',
        'cs': '1655853f54f7637a9018a3a6a50ec2f5cb873a0da43dcbfdfc39cfd78f99a137',
        'cy': '77074c66408041423912b27c09d4cb5dd12b266ca83014aae65a99bfb41dac02',
        'da': 'ef233dcddac2432591fce64cefe57ffb9a21fc3e905897857457420db642d961',
        'de': '420717f39b310c02d2f02cd0c80216972d53a911d1dde9951220c19882d7f2b0',
        'el': 'ee2c3ed9c9c2fc364e6dd440df683a621f503565f0b023b352b70c809b16deac',
        'es': 'd49c0e6ef128df1e9112b706fbd5324bcf8bc8b6929e91b74e2359440d4c242d',
        'et': 'b9142315ae49046f9901fbb1503f4a29d57109bc0d0912b5d97aed61a47a9bc2',
        'fi': '7a681261876beb596d6dc25dfb53e0bc9d785d76fb1bc453d551c2e6ad92455e',
        'fr': '1de734983ff4eaea56417a38e628899cf1a82886a3e0d84dece6d57169a0e0e8',
        'ga': '8738bb9c85e174706fadbbe9050ec931b08df4feaa3fb800da62cefa01746253',
        'hr': 'c449e7f9dd6259508481d02508ae7293e04e794606c6e021e55e4a715bb5c07c',
        'hu': 'c1745820c72aa7735608662ad66c0cdd1de9fc713fa631f710b8f04f7c3400c2',
        'it': 'b77eb915ecbb805e924bd58bb5c73d0cb0829b2ffc3275cbbf5c24c0e2b44ebd',
        'lt': '5fbac8126cfe0a2581977592d0043976d349a558c2acc40b4bf6e6b1eda4e45c',
        'lv': '4719eb3e9ef6852a10b9d920f1c35efab473a5be721cd2fb3b1934f4df0ad5fd',
        'mt': '45a2c6c837759185025876d6ceea615aa2f584eb9eefb4913c17930201889fc3',
        'nl': 'c857f4f60a27895d229bb8d5737eb6755576d4bb4301260a6660c0d10b89bb70',
        'pl': '679a9b45d0beb7416522f8985c0000a68fe480bbc1fa941ea4a80f8dbd2da2e8',
        'pt': 'd3c6c8a7c4b4bcec18f67f0672aacb1e60d96897cc61d5b703c83f22a86f6ea9',
        'ro': '1fd8f1f1e22232b242e6e2a3d288bfaf22717ce7b161387ae1a9b92877244993',
        'sk': '68180affc8e59f35e7d7efc4c752e36d9d3f4236be73447febe6884994a72995',
        'sl': '0232428c398f6494f258b5a6cb89f2c1dd9cc1dc508ac2cae54b9233901ced4f',
        'sv': 'f39cac26c94b4d564e3adbf090369fe2b3b2df11779117d53f693eec0c755b05',
    },
};
