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
    version: 'c36d14d0f06388a6',
    digests: {
        'bg': '9889e410cf82f13087fb181b3e90db17d18283b0ad18018af8ce391909767894',
        'cs': '4880cb6dcd681417cce14e758e02a4733dd0dbbf4376b79a425ca32a0ce5949f',
        'cy': '5caa9f3e44ef919791c1deef94088c620697840799c67b9475b385d9fbe06867',
        'da': '495289b812813b576f4eee4a1b3989959811c864a26c36b56ffcf6f3ea8552a4',
        'de': '3516298c0fb17ff8b42f82a31e99385c3d7e86e91f149d17750502a6c533e063',
        'el': '527f9103ecd7f1dbba081fbd407c7fce799975bfade934425b79f2ba16c61e6e',
        'es': '63794c4ab76ed12cce9b78504e2b995d5886cb0cb1e0565bc250e60582f87b88',
        'et': '748d9a4c6858cc38167d632c8d1fe29c4e24cd643f7903c50d8b04d24c4b39d8',
        'fi': 'fb9ae5a8b134c5d45a40c52c4be4ec1fa23f63830b2e5b0e05d0984bc1ad3471',
        'fr': 'efe900c9de09af65cd057a3786d92c9b4b191c63c3c7a8b198740e5ca1b875c5',
        'ga': 'e6780f727d4bbd007a2797b67c1334a8aee924efcdcd3d672adf4939a75142a4',
        'hr': 'acb9d1497e84d24d2300bd423cdefcc71562127a0e081bfdefabb787c6c70afa',
        'hu': '2119077880dff44944f52e6f24a9dba7806894ac21247d6bf82e18e85ca9199d',
        'it': '585a0e2c32544d3054d9607f1eb3a6fdfbe9f85125016fafb006f062e5875f8b',
        'lt': '2c9dfcf54fb18f33a33be8c86769e19081a9aa4b39b4bc5447a360fb12546fc9',
        'lv': '7d195913106c86596398aacaa6891ebfe7a07e5aa37b8affec2b132c9218a823',
        'mt': 'cd220f90ea8c191d1f376d76f1b2045e7de639336f89ff286136e41d38456ce9',
        'nl': '205ae716adcbcf82caf5aff597eccc3a3064af569c9dfebbc68b3ccde50ad4a9',
        'pl': '9ced7c0313cb67e6bf3862a74700ce1d21529465bf8f9579127198e8651c3a88',
        'pt': '25f922937271c93bf25ba0ffa8439024116487597993554a920280a56c736809',
        'ro': 'c361ded25336a1f9d8c58296bfbd3ecde4611eca82b1450d0ac9c7298ee046de',
        'sk': '39fbd45994383b03d2d16ced31ad52e975bcd2601174e473e5c5628bd276b0d2',
        'sl': '319e8450ad95e189c12c1b1127a1e89b1d87ff25d406c9eed2efee8a783fa9bf',
        'sv': '24507db71ca6f197b117761cc93350b24c776dacdd7286fdc7173b3bfbdfad0c',
    },
};
