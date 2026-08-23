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
    version: '67711ee61f50d00f',
    digests: {
        'bg': 'ff76adcc1f700f17ef309c54a406becc6c36eeb3221fcbb2b90abd4c507bf01b',
        'cs': '06832d07e2a9a1d1e3afe11b886dc9f59a76aa77342bce1738ad79dd3d1fd24a',
        'cy': '60f63ce49e4f88e054ed5d2384d711fe97263da3962a7e1fdbcf8e30260f73a2',
        'da': 'd362a9cffa62ed625f71a5656517f97262a4c9420275fcb82183abc6926d6abf',
        'de': 'd93db57d4f2aaacecc714789e355c4b2c78eea222b9a740865ef5b15352874c4',
        'el': '550078afa580daa1c77547e8c3438a434c8481e61934bcfca608f715e10bede7',
        'es': 'fab87ea3129a2a0788805d2ff7fc2e36e057505afce61a034bb5b280b3ca4ae8',
        'et': 'e360127082cdc9b61471a03048108fba6d2c1e2b7e5ba79dc39c0be270867be2',
        'fi': 'a2661e8b39cce5bd3e0e68f5c02805892dcc7633f77a0e572e2e38642c83dde0',
        'fr': '22374947cce62c77b04d9023eaa174cb0cd1d52dba0bb3c1372b2961abb5575c',
        'ga': '1e2d597781663ea436377bc87ee1f8e9fed9a5e43f7600568fd1fd5dfaa5abbe',
        'hr': 'b2d2f2718f07ba080172e81ca59b2ffa2e1fcbef7dff2e8c87847f27ee6d23e6',
        'hu': 'fa84d7ca949ca7f7dbb83fcd1422507d88b1c062a1f19f49ec727d2e665967ee',
        'it': 'dd84b9a8d560d255b3803b1e26fa8aeadaeca55291fad5bb4cfb577940a720fc',
        'lt': '648361dec553c98144b0b27353e23727b47339c26b9ff136961dc6eda7d7cb89',
        'lv': 'a63a2e17b8565316110e51414aa34455df298841e8d79dfd3d1764b98e45c9be',
        'mt': 'a9b80eb7695c4f89f47ac1a98dd221581756f338753de7027b704f71c74c1ea0',
        'nl': '5e45002ec6234222d612596a167dae86eab55f2d0885c2fc749da7f18d03c77b',
        'pl': 'ce8a9c37ca64c9ca6e7de71ab491d7e58e668355681b6267fee33c66a73cded8',
        'pt': '572bcbf50fb7f92901ddb1abcce4e876f02fb72b26531b9c5f0441c60b8daac4',
        'ro': '0cfcf7a193e50b9d76f56fc6a9671ce6343fe126caf221e22ee5b20557f33bf2',
        'sk': '824784c70fc85f2ccdb2ada3dd39d8db2a3e154b9592f8b8c1f5276ad277f406',
        'sl': 'cc3e8fb1e488f6e4f10c5e2031a88f343b4cb84075101d752d969a34471153a0',
        'sv': '8189cb911f90a928ff7911a14923246884d6720450233d8eb6ed38dd98fb94d2',
    },
};
