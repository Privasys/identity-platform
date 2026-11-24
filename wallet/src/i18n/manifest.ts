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
    version: 'cca75a66852d657d',
    digests: {
        'bg': 'b22693a6efecbd6436656a0b86c4023f2dfdb90d43204ef6950a5a1e3d63dcfc',
        'cs': '83fbba2698cdbd4297a3c9424868089ca5727da535356d035622ef57df5da9a5',
        'cy': 'a29d106469add731bc92c60154c9f5f27b2aa8bc70a9eda531c79722479898fc',
        'da': '62cd78c6ef3281977f085be0c9fa0aa0f026ce5b9ed7f87d466d5406a454789e',
        'de': 'ff1ce5f008ca07e930bda19b283cee224dcb9ed629e553b46fe2439064c70380',
        'el': 'd2741302f731f7f1d5f0f06366ea2ec7d1b01d8b07772179cc8912288a8bfed0',
        'es': 'e5ae678a93da8fbd6adcc8f295697c23cb3aee70cc2054363e11583213941ef0',
        'et': '58919bf3a0725cb023ccd2015751ba6d760d259a6a9466fe306b28b068f6da4c',
        'fi': 'c867b47b88c55e20270417200e3c3cee5bf82b0b5ad30cb225d6a5310bd6abc2',
        'fr': 'cb1d25c25074826545b0da7015e76b333203d740fed482fd75fe15424b10d511',
        'ga': '0b83130ff8586b5459afcc2147514188aa81dd49a136859c3946d45c9898f330',
        'hr': 'ac780f2f1e9240b1df0aa14fdb7a79026291c15bff84febc6972c503383e158f',
        'hu': '7e6668b549a02b6a021f916a644447f38cda4ec49caa5fd2c403cb4bf8976de9',
        'it': 'b7dab99d379d4f7a2bc7e4b4d1327aba0d35022046cb87c75b16fc6132c74468',
        'lt': 'eeaed0c5e41daf69044bd205a73236e3926ff71d66a2f8a3d3ff6bb3007c6af1',
        'lv': 'ccb74dba220c12f8caeddfb19d2fac8dcd3972a8692c80ce6e69bf7b35bf73c7',
        'mt': 'f81ef793aa606b5524fa80be96de939e75c32014c6b13230e35425791af1ce26',
        'nl': '8cb3665cbd5876436bf7995115d9028f83b59f00c88cf4145bedaaba39d694c3',
        'pl': 'fae8f41882d8e8d1af84828a33148c328dd564767066260433711bd747b9b950',
        'pt': '15344ef16869b37a498adfadbc09ca59510aa9cfe4c04bb9d4918d4d00ddf032',
        'ro': '2294cdbafe10d79a84192197199f05528fd622ff8a55696a2c2ac772b7297076',
        'sk': '2010ee3dd212f3baeb1e8d60d7e2ebb74a183b42be6e5796a4e3a3ec7b7eb19b',
        'sl': 'c528477fd53ced1c834ef53a53b1cc89ea27f073c7af6686cdc1b524fa85613d',
        'sv': '1a7118c9191ac2227ca71b6315e32012dbe75c3048dd944710a4b2a68edf0075',
    },
};
