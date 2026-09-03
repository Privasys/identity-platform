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
    version: '396bd7cce428f187',
    digests: {
        'bg': 'd37ac82bc56381030647fc710cb4a4442e6bad309a9c9c45cb31a369ff9a78ed',
        'cs': '7faeb9583d97775a0385b36045fc69df69d273250dceec089cea2f2bb3ec71b4',
        'cy': '5620be27064a24537588f55f549247613f946ccf747132aa41251c00d6f5899a',
        'da': '6eb022e4a36c9a3daedaa6b03781773b03bbdc2863ae430af2bea47ba5b22b78',
        'de': '22938ab057c001626d7a43304359e4087c20b1a67bdf44c3c620fb4db914b1d9',
        'el': '93aab1bf97bfabcd7ee138860aa8660ad59d0c1cd1ceda275add6e835e9a6ec9',
        'es': '4de0124a285cb2fa01eff96c835a62014561e46449d7057a46167d091ead67f1',
        'et': '9fb84957965690120c757076c9d8ed659551399c757dff5b219973672cc1da6c',
        'fi': '8232380b0e5459f30f2674de1332bd046d220da3ec61be57ea1d62753965bc5e',
        'fr': 'c1bd72d90caadea02e543232c4fc6937248bd1c7adcb061d9c341641d91a7320',
        'ga': '79e410a9022e604d8eef711545548edcee850f2bd98b2e4b6fe32519857140eb',
        'hr': '527fb528d0fde41330facab36009d7597763582f19d39c518699b9c4524f1d06',
        'hu': '0d29848d40fa4c55c81f96cfff6d3a78bfdd7854a4b308ae03adcf278b57f773',
        'it': '4f1b76de45a07674bd63b645a7f8569814515a3244846014d087cc98078b2ffe',
        'lt': '39234c1b5795024ad81434d506b986008d81ff3db63f874fac114c768809699b',
        'lv': 'aabe72fd858e1f4d0d5d7e2d607eff7d6925646b104a7dfb5b3913e89019855c',
        'mt': 'a95913534b5250b77712820d5487be2d92d4004e0b742bed7d6c6f1768b6ceae',
        'nl': 'f907dbf909e1a478f17f5b76c994143107c4bdd8bb96afdc373ba52b4e1aee0d',
        'pl': '87172f9e861041511903546cf59269702647354fa26687dbcbaf6740b719ef22',
        'pt': 'd6c294b168fa60c3dcf62bc4e57ff8a7040110a2c369a101e28f7614d6347097',
        'ro': '111399940f04d8f74dbbe7fbde195fa7c3c8aa9c8a9d61c014955e2a915330b7',
        'sk': '60151ef706e8874e7a7a5ac33ff4920de93863fe52363c443e523e3cb1bde29a',
        'sl': '35086f8ca10662c8c29b055f5081e6748638378da1757edcbebf964568a2b24e',
        'sv': 'd20075de3ffc81b74332e00b0dc06711bec0cf289515ebe3ffe04f695aed854f',
    },
};
