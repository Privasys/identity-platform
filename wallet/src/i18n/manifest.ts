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
    version: '6574c2ec0022e3a8',
    digests: {
        'bg': 'd3d8545713e34de64a521a82efb752cfffa6d479f047827095c6f6c71504ac14',
        'cs': '4559cd42647768d5031602cf1a1659d3c646a58facc3ac46cccf9ccb8f377cf3',
        'cy': 'e5125d277fe421afc484a400133c655933a015535279dadc47e849d7d648572f',
        'da': '5bdb4639cf7b3e4a834f86bd9b769bf618e662e1f1e15b8ee794897fbe48cc84',
        'de': '1d7ada2d561aa0615116935dcb33f40fb1a1b429b575f6bc287575e7fa61eedd',
        'el': '45877964ec2a7af0e0219e337c7cb9bcda0a7342a02fda7f0c7fe41f50c21507',
        'es': '888b16d946044b96a988a841147ed99b78b35b28dce48e6d192904d90dba60c2',
        'et': '77ad16349b43c0d4905ae67624810413550324454e08fd7ba5dde29549120359',
        'fi': '7d264a06af19ffaa868f716cb1ae3ac98910fc008fb9ca20bbfb1c813cb10a58',
        'fr': '87942e21c5f6d73ef2aa01e5ae3ccff8747cd5201594ca039183b9b02f1fd705',
        'ga': '317547e5b690abf39507408753182f3ab7e7ce41cd71ca68515cdb49f9fb8803',
        'hr': '8950dedf0467326c5a6327db760ad5c9f42ff76f31bbb8747d50cafc52497b71',
        'hu': 'd6c89f4169d02d7ca6ccb603ee9f273cb87f0a83fba940139cf273715fc4472c',
        'it': '825815283a92a59a4e2cef7745a34cac040100f1981320d0e7846e3bfe749511',
        'lt': '8038f6a44be0bb492391d9cd5a8be8034b9ec7695d56b76245115527d0e0f48c',
        'lv': '671ffabba88732be348af1bd755558ba9b6820472f0c152735eba20f1cc14140',
        'mt': 'bd8b171928da741027720cd8fd78e24b2482827683d92598ab75888ba0382a14',
        'nl': 'e0753ec32d9e5c4e764580153fc0ae9aa79880ff21d0af29b53231e264a84eb0',
        'pl': 'cf8c9277087256fe76dd6f98b21a4b5c5c62f30c21c6bd26a9dd73ebe14edcbb',
        'pt': '5e8f76f8106020db59c3807b1a8581334e585fed22467399d3881ac0de2ed0b0',
        'ro': 'dba362afee63719e755ab4b7ded5f2bf60d5324a9d83ccf046175247214a22d6',
        'sk': 'd6d2fb6f228eff8e1974d2a604539b99b7e664b88981ee148b1fade0ebb1d168',
        'sl': '3eac102f820e83f8964d74d3499f934ebfa588720d81c1e24a3828a16a569cad',
        'sv': '077d4ff83d837b356c9687165ee2693c3a00e47cf87748f4ef5b9aa79f710f94',
    },
};
