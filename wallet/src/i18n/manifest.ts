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
    version: 'edfc94ce1e05c9c9',
    digests: {
        'bg': '8ad24ddc89d74270de583fe775504d535c97a9c51927d36bedc35246730e7ec4',
        'cs': 'be795df0fa67b945c213585e609365d5ac821fc81a2e406578e5f541218b5f1b',
        'cy': '6d4e60ffa10acd2135fdb048998d3164c20a107566221e30f2df3dbde81e3f07',
        'da': '7a2cd21bfb169aca662ee031492f7dbe5eb834793a07c7d378993597a1f30f17',
        'de': '437006aeb09f4785c4c12c5bb54fec513cab9cd65d91b74ff24129cf6725c7c5',
        'el': '9330e331c1ba9d3acf1197dae7f8280accef078269ce8824df9cd2ed1e755032',
        'es': 'f072408221bd4dff81a4f2c3b1b0530e528018c9efb9fb4a3cedfb00a4df1583',
        'et': '4fbbd50406c8c65308cb7c28d455a5832822275c844b2d6b9f9cdb30af74a3b3',
        'fi': '2e5d54debeb2e56f597dc477b44cf56f07be00e5a3bd67f724a52c249999c03e',
        'fr': '34d09be0b1a1978982760c7bc4352d14a8eac763f9bf4b692eed02917eba13db',
        'ga': '00f5d6c0ca8f9f07a6d7152310cf18c65044beae7a80541566e30cc120541b86',
        'hr': 'bb2f85cb7429ab10aae5a73d2c46e8dde47ce31c396aaf7684a4b3781ddcfd1b',
        'hu': 'cbbdff170ba4b02bb7e100831722493dd59fbab4b222aca69dd9c8a4e0a5f5d5',
        'it': 'f65e881efe052aab805edeaa1ddaa99da10163f61fc15f1a64a9a739ed7a5b01',
        'lt': 'ca9ec9ce178b8d530782630e16a833521246ffa6d6251843ba74584693fd3849',
        'lv': 'af0381406e435f32cdf1081e0845f200f223f11481b993f509e9c985001b127b',
        'mt': '8070e3376ed4b48c4955425a94bcb1d4d78da28a196bafd176769c6844d63fb8',
        'nl': '742a19204d808ab41dabd091e6b821d9c953ed8ab118acf3670ef86f6fec4cf7',
        'pl': 'aeae5108dfa98bd72d5e482657a886d72ae7b5f38c9d4c5d78186e3d79c1b419',
        'pt': 'cad35abb59dc6f7a4eddca5c8396937cc5443a62aa647adda03a65a37fd6b230',
        'ro': '1a0b9d8bd5a8d7a4fb07224efc39b73c98a5b99cc0c5d425e4c90eda70c98ad6',
        'sk': '8de882ac9cc0d7b4e54e99f159f6b62dc485fa58e990aeeccb29a481e9f4d885',
        'sl': 'bdc66ef5c4b5e91ca71b7a742e4ecd2a89fd7dff89109b484126faf3f7091607',
        'sv': 'ac16de5788b31629b85288a6cde391757a3340e678cec4a0b5cea6ae05fc08eb',
    },
};
