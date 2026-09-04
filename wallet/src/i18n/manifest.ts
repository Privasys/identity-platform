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
    version: '75db1347b63cdf42',
    digests: {
        'bg': '57a59c07edc461640ee6d672fe9ca1c3c83b8fc98f5cec82676a99a912f7113f',
        'cs': '2ce294e923039c61ad36821ff03b5e55e0269db7d7e3b522b6620869c39abefa',
        'cy': '35579eca2353f318ae8e2c28b35a5a4b970a19fe97828dbed07f490942e9bc04',
        'da': 'ebc471869dc5d8871a193ece0b2b28fa24366964a04c5e0602ba4052b11ba7ca',
        'de': 'd742ce7e1e7afa75ef799413c9f9f4317fa725359cb225cd4fb5480da1310671',
        'el': '0afe4f5bdac20a81110050960feeb64f4d3537a1313a1113bca39c2cc704559a',
        'es': '5c542b3a77c60084e31359f101430d3da364bf4bbf37d6fa8b991076f36d2038',
        'et': 'aa325bc456195d0930ea81c172082713c2d7205c6ef9a3bc79a31e6639f2784a',
        'fi': 'fc9168528f3e92ad7640de800a923ef6350143cbe28c857f1698aed3e0216597',
        'fr': '6e70d760a38ba5bc1111700750681dace9d79d194a1b41b22d8caa59734e8594',
        'ga': '236e47c601fe5f5950a2131a8c7d042103e58d2dc8187396b61acfe28c38bf84',
        'hr': '75a5b612558f4287508fc3002deebf2fd73461933cfca1fd630e0f35c64b13d5',
        'hu': '93f8340b84d8861539d4968eb82242be508cbeae7a135ef9bbe122b1ec905a77',
        'it': 'e6cac8c10d4fc055cfc72e8880a1ca7065df13237cd0e71bfb3aaf8e06857011',
        'lt': '405be62d7209854b80ea7da308799385a4495b2d63f2c1dd6a656f678781f42e',
        'lv': 'dcfeaaa85558d1cb118212989a2785db81fa1502028b29c993d47365efaab340',
        'mt': 'e166a0447ac84ca28960de5137c4501f13c25bb13a343285954008ab22fdd58c',
        'nl': '8b45be217f7416346d9257141ab1404147d508f391f05963ce4dd04e62e36d4d',
        'pl': '72f2386dfd244e970e21a4e15d279c40c5c825df88b34bda39db770ff96cdf19',
        'pt': '435e0a82301d0ad739f16145c59139d9a4412f5452af42704b731c1801a0b07e',
        'ro': 'c5dbde182fc6dd25f35bfcf9cc540a2b3560444d63d36ea7c53a83ad1f79edb2',
        'sk': '0893349885487ab0d9474d7b30c04bf9d53258be6e06ae52af41f79e3970e456',
        'sl': '001470deecdf02c479be3c86f34bbc9be083254c27c67215bcde03d8eb5536b7',
        'sv': 'd79620bdad15aa77938c33a297ab72c5be790189910520eecb67c6002ea17850',
    },
};
