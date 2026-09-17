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
    version: '1e90b8e7d8f4adb3',
    digests: {
        'bg': '00f78fea3a5878cee4cbce3cfe14204112d8af52b2044ea33ae71fafb12434bc',
        'cs': '904b393ddc24735ca7aa45a8a37a47317cac7607367a288c331cd09346c78a90',
        'cy': '21bb60013de72e597c0ec2c174ef120f57ef6b1fcb17c6b539f27f18f02d7764',
        'da': '352917c958611441ceb9837ea9f4c452c510d70a5e4d769dd15945610eebce3c',
        'de': '73e7618a83be9f14612c5239b43720a869b6f1681a53fedcbf5473eae35b6416',
        'el': '84d1ed4780ab77a727278d4a5218296bf80f92b6eef2c3563e8ad4267e8d0fad',
        'es': '8b494d30aa2c3562597a0c890739088c6f8e81fd9d44b4224b4a3af1faeedbb0',
        'et': '8998407a4d6d71a6c6a6eb57b8affb4fb693ae6f61317cde605b3c570c775378',
        'fi': '738c756efc450213bcb73b41bbefcf60b20f246ca53bf063ace4f43195be2da8',
        'fr': 'dc0dc309f10172b460a9e90bc30cd66104e75e9a8342dfb1ac934e7e78c42c9d',
        'ga': 'bdb06a34dcd0cdcd9574b0ed03cd571d5d3328e44da5ade1925837a1966dadbc',
        'hr': '489795aa1b2e8c8aad3ffc4f9b3cddde1d151c875c5c501335017b533b225196',
        'hu': '1701051566ac02e216423b521997bda4cddbc88e1ffe409e91ceed7551d094b4',
        'it': '7a454645df7a4b4cd77cd3945224c4ea0f6c9d98289d922a9c64e50d0abd7c7f',
        'lt': 'b79f95cf008100b50ba67a239d3130b5c43911df2a10b6865aae14a0e0e4c597',
        'lv': '28e68a19bb7bb9935bee071a9285656e9836a0849205f53102283d72c24b0ca8',
        'mt': 'c7b85fe20c21351dec6c323194f414999fcc343cf727bf9abbef1a23e4ffd075',
        'nl': '92d3566179669906c5d93443497be1590f8abf7073fe9fe9bb4ddbe4ce037f65',
        'pl': 'b08dff2a28e152244655d1ebd73ece2deb823e90969085b538eb992f9219e11a',
        'pt': '4814da4709f06d74248db448edd2c7b5f90535e0efe4d408db5909fad1720771',
        'ro': '6ce91545d2e3a0a4ad4883f80923a930c5be426356e754e159bd01e7d13aa084',
        'sk': 'b9d06926ee4ba0d6c3d9caf34a3f1ee53dd383bf394142baff9d7fdc69722f55',
        'sl': '15c1f5579e3c8b4f061200dcd7168d59ee305a304b89fc4500cb78e4da098c18',
        'sv': '328e754bf830421ad1abf53c1b4a706aa4edb8b7999f132ff4519f35aaeab8ca',
    },
};
