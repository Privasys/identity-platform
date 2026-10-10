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
    version: '88f03ae7cf619f33',
    digests: {
        'bg': '8a6ed01d90aa88e1cc82f76c21e2a3152f9676bdc7b29c7dc87983eda1cd6173',
        'cs': '5b1c2d9623634d4419b4d5be4efb9da21558f0580ad7b5b89d7ac9cd620aff4b',
        'cy': 'a935a1c7ebb95215da80a30391d9aab5d512774f406fa636dcab1f52a90d982b',
        'da': '980393f4f9189bc9d53283c1529160a369302a18de13fd4472e0e7c49a9e5508',
        'de': 'd72d1ba6f07fcc449d52f231bd469a57644ad8082b3e65ceb3d9c006e0fff160',
        'el': '029726bd75bff9a743b7b1037c25c6aea2b39a05c07a8e63df46e5bd25fe882c',
        'es': '1d83c48d6d46cf68a92b82f953eb1714b9bb52d577135adc5a81ab1e75797880',
        'et': '6e5eaeeb229005faa360da6800aba263c8ca81e7f39fd2ba7c5dbe69952857c3',
        'fi': '0b3335dfca0609091e8e4df52a2becb83dd1351266fcc1a6e44d0dbe3229146c',
        'fr': '8700004111f852449546c748854d81aa72f5f0dd4787a6284c2262ecf0aabc2c',
        'ga': 'b49080f06d928f3148fc3de4e1fc791e8cfbd18ce593c762b6d2705c3cdba58d',
        'hr': '55b30f6a421cbbf170f14ec2e9b555638cb79053013857c3468b3c61f85c7f2c',
        'hu': '1ad5c77583393ccdbb40e6e54e69805111d9dfe2ad81adf882a78e1fbac1b25d',
        'it': '56a2a6886991953751ad214f4ddeba6a22e96e50af2cde7dd9f969e0b2279069',
        'lt': '44a4eb40e2cb64110892107bad9d055d026e05d3634b3391e77bbcf8d33ea448',
        'lv': 'f8c22464a98f3907e30710c95f33d6e49d195ae26fb1b5caa48cf369617a6cee',
        'mt': 'bc0d4afdc8f2c3bcbab83cf99ad2305a5d3bd598e4357a61f279535e4d6abe3a',
        'nl': '39d594d398ef21015168071172aa6bad2965eff67c62112eae4e792f212bddac',
        'pl': '34c3a8322c6ca6224302677e5b0c420fc190f78a41cf4e9ca90961ea107f7b4b',
        'pt': '1801a0dc3803cf294243d5d15769ac1cae272c042b15d5ec690f35a041ecf475',
        'ro': 'ed852cc533520bac570059d45f0e157e9254fae6e4362c0cc204418b9f111ce6',
        'sk': 'c6f946e6e86722779a709a45a69f5ffcaba6222f49b2692684c4f578a26d3a1a',
        'sl': 'b2269ef298752c30f4cd21844a0d22f433333a3300e023b27ba944a2eccee323',
        'sv': '8ed2b8ebfaf2ee88a37ae00ba3c29d2370a2af475eb801ff26dc49ec58905f84',
    },
};
