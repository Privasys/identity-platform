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
    version: 'f700a4f22bf5a2a5',
    digests: {
        'bg': 'ee37d8a3dbbb3b27018608af733b5d1d31fdf0cb8ab8366bcc84751b081f4d3b',
        'cs': 'b111658f22004dfd07e5f27b39fea3ee3f073bdf4d878bed40a69a3e3f70e0d4',
        'cy': 'd305bad86edcd687a2cd656fe37ad37123e1878dc84c19f04cdb740af4a34eb7',
        'da': '2ff440b2871de45b5f94ad4a1ebd6c1db2ffbab690c4a8bdedf2232230f45bf0',
        'de': '7ff9dd86c7a4346640dff8f73d70c47e5b218a7df123e9e432beac23299128d4',
        'el': 'b67dfa65cd442d8475d1cb4ea4d7a65e7b8b23e6dda3f2b3144a6925517058e1',
        'es': 'dfec9a7adf06a01e1136f86a9486e4aafde2322ce02dc224907e683413e1a162',
        'et': '9e32bae252fb1c975b0e84c657aa40601d980ea604cf589ca337aff291c88bc7',
        'fi': 'a2a062079e2180be04b7980adbc64af0e1de626a40c491da6f7f116bf70cb5de',
        'fr': '748e34683551353695313ea6e67bcd41ef1947141dc6ee8603ee0ebde2abcd69',
        'ga': '5a8f5c1d56df564f4425261a9f1f221df3ba129de9d3937fe13d653acada04c9',
        'hr': 'a9f144ba3e685ddff25043cd4cf62810b959242e24d3494f202564593e5c3131',
        'hu': 'd9a4a4737339c5e2152c0380769b006990aaae662f5bc18ef8770dc40439312b',
        'it': 'c92a7e5f2df6ca5491752b5e062b403e4306b4b826faa699e71b454e70f6cd66',
        'lt': '153562163ff1b37a25e819c2e0c2e50709e2484765d76c2c831f96c7966cf194',
        'lv': 'fa6b3ea1e0bc53f5c267b49613c803834d8bce7a74b26208cfd9bb06f9826c99',
        'mt': 'aa7bca865ca6b3cd57fc2c2b0ff4847b27329ce71c7719a05c61017368baf9b4',
        'nl': '319a3bcda2f3c5c541c404be827aeccc7e7b04b53e3cc9ff00a7a0365fe23621',
        'pl': 'f35fa5895dcf69096dadb32436074f7f52db78ab775a18b7dd7c5bd693fcb276',
        'pt': 'cfcaefe51c7e8a87e1ab2509ce4d8cba67791691542c0e061dd713feca31c973',
        'ro': '65171980184d88064394aba02f8da60807f5235ebe111cc7304c8b61ba4dad50',
        'sk': '6a76276569064581e0b57212421861c4a740aa654c990dad4804cf940b5c822c',
        'sl': '24317f453626baff778baa4e4003e3bf931aa9ab49642a589b2546aad5ff2a1c',
        'sv': 'b88d4667f9e10a3344e78831d6bde9dc9ac34b6a5c878d8ca2d7ec461204ebb7',
    },
};
