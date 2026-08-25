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
    version: '0db02eb84a6eba48',
    digests: {
        'bg': 'f8c478edab05e6af3d123992a80734994d88312334ac86a648300ed0b7410a98',
        'cs': 'a3e17b7d2cc16798d930d876977d0b51cbcbdd4bd1fa07d4a3d5b1fba94b2dd6',
        'cy': '0d2a108442a5acbc1eac313e8f7792da05f31f430c3f1f8932127411bcfd070f',
        'da': '02e56bf927d0f368deac45d54fb4b051a88db526f5af42ad53873675a50a175b',
        'de': 'fa827f6d8fec742811e0c70eb7752e8d4e8f0a4fbce7470f9efc5adf8e1dad16',
        'el': '0fa2db24490185d98046e5c9c3c56de6d236baa18c725578e374e1ff182a9352',
        'es': '96694c9751d7b39b74f77222ae2dfae9c545a0875103b5418861f596acb82153',
        'et': '2fedd41f2d0449d36142674935419c6755500fa175363347b6366ee60fac6e6e',
        'fi': '47644219a19dbe8821ac5a6266bd3a845eb6fb05d78fedb8a9606fea0dec3265',
        'fr': '58dfdd4866353993f60e1a6cc6e36a263c7e59a046d164f0f7d6462e89a62cb9',
        'ga': 'ae1d7acf25b1e9545deb4a8f01403375cf63173275113259f2c586d51564dc8e',
        'hr': '2ae1aa42c89ef364f8afd59646d82174bea881961c02515f3a64f5a797e858fb',
        'hu': '8dd9b712788d5b6962f763d7d1c74d9efd3af057933290238ffbd539b31b670e',
        'it': 'a1ba3d068d7d51f9d467a5b971b3ca23cd6d0b821a3703e20c62d86b1fed4628',
        'lt': '1f0dddf03fe1a6b07c77cca066488f955edd967fc3715bee1f70fc27ded0b080',
        'lv': '9c8e1f901d073b2f2fb5a22705225af559b40408cbdb12bfd384907554ec583b',
        'mt': 'd8fe109e94939756d838306547402a250c0d3f8bc196a883385f3556c37c50bd',
        'nl': '126f4ba14e7b6e4f25a53fbc917fff7168c54740f118e604a050cd29d84bc359',
        'pl': '5aa30f1f0607033522fb5c57e68454d246a2490ba04e28ea40ca42419b0af933',
        'pt': '97ba063b373ed016475b216c23f12ba90ad1c978425ab3ef8a7f9797676d01bc',
        'ro': 'a832e3cdd11b76d8574ae9788118e8b0cab5aefe951017326929258eab030c49',
        'sk': 'd68843bb064d49c892ac2192d3105588d43f73237f59a2386ff029597e4b411b',
        'sl': '917e0a8a6580c65cfc297783135b95764249f7b24be0b699294efdd8aa1a713c',
        'sv': '1ea9e1943e83fb28a502b892e6fc05299b0eb34840e3317652a3969bc8f411da',
    },
};
