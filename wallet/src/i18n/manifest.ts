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
    version: '8d69724890fbf302',
    digests: {
        'bg': '38ee45f8f8114f56fb1492d416b7bf7365d97915f785d9d1b45a4607aa15f35a',
        'cs': '02f925a5ede67c0d05aee62492c41c82918c525bf54812ee963d5c38eb07f6a4',
        'cy': 'cef239a6aeeafa4ca7bb206511d8efbc2096dd7276e1c38e92d392376283b9dd',
        'da': '37d4a84d4163f2cbf3d328f1bd8d28cd7c5b4f39173b0fadca4ff3696296ef9e',
        'de': 'ad2540d4a88896145a38f25436c8cc4ad8e86f69272b1436e7c924af1fadf1db',
        'el': '1dde525290627966b1411db2d3a02bccf9f3758b7e39442a8ec5d7f91daff103',
        'es': 'ea75ca101a122ed9fe33d6732987251e4d1c8659e8fe78502c13832785e191b6',
        'et': '037d4f35f80b79c70b76fddc207056794422379bbb5a8f1006c94821f2d6942f',
        'fi': '5de48852aaafb1fcecc8c63bceb4dd1bb515dea0b8a1a72e57050e98dc00902f',
        'fr': '69a0d20f9b340fafbb5a093bff66ec77f6902f8764c7a8539f5b6f43c9fc04dd',
        'ga': '627a33705d87dadd8e2c18d9d83e3597251b42e7f4980ae332077e6173f75628',
        'hr': 'f9b4dcdaef4bb5cdc6784b66bc61a101f850396db69a6b2fd7bd34e12529d8f0',
        'hu': '814100262117166a83e2ef8aa9f848072453b19cfdbe7657a78b76bdb1b7bdaf',
        'it': 'e94c101091131ca356f3c17281f07136ac6dcad0816a58e85ab7d18f528f831c',
        'lt': '25b13c7990ea4b69541c0f7434814f8a1fe2488acbc9c60d9434d7ae099efcd9',
        'lv': '405663339564a1404f3b1fcfbf1c2fd4f71e9ded7ef7d17828b875605227ff8c',
        'mt': '636d9cc8130493f540659dc3c3023d65de041693a542229c05514fdb015d9557',
        'nl': '60b207563324d693eab525931fefa2f3a551aceb68dfaf79ae457173ada629fd',
        'pl': '281105651f45335d36d98ffadd14a3e70378e2bbb7ad57da5ba643ec6a9fea3e',
        'pt': '5a75fcb5c5b765701775abcecf1c6227a8339cfe0b4e963afe71880b96525d59',
        'ro': 'da893e2bf7dc34a9b2654284af4972df8964dd2dedd53774654022c58b8a677e',
        'sk': '0229749d93c95e8d3212f8fc8e68b1221a352f528441f266ab500ad623d90014',
        'sl': 'ebaa365797f0300997b33fd64c53193c2b0ae8ebe9c22019e97f791037e524fe',
        'sv': '21ec4f737c7e07e4f00e21f3791564a86fadf35476b628eed0ad7209d36022cd',
    },
};
