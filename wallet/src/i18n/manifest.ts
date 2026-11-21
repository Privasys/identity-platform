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
    version: 'b210fa3a1e9fe9e4',
    digests: {
        'bg': '5bbeeb62d77ec944a99b55fd375d7afccac857761b8320bced33bc52bcec4ceb',
        'cs': '1ac52a50e33a6fdf645a165c34eeda6214d0d4a04dbd7fb44f1f05bc6408a860',
        'cy': '04ceb03b27d93d1a8cf1b1598251f0c8d19d6868a70c9b0fd2deea658d412ca1',
        'da': '4b61c44abb1bef1933d6edd04e9f708387fbeff44c4ef32a29f122ba4609a2ae',
        'de': 'e5a8587a2cb871026d3d8b25d7c4bb09dd13eb73e72a2e2c0edda5a9df2affec',
        'el': '04658f5e4edfb391ee3f630abecd9bb3be02ab79c758350de3e34f8eef735e92',
        'es': 'ed1aa2bc6e5057f95f609c0e62f73f9579d42ccbc4a3c61cdcdfe746d9f0efa5',
        'et': '309215fcb19170350ad8d63efaf914b4f91f8cdab8ef937a7c87b1848c3e9ed7',
        'fi': 'ccfcf1fad34f65d21abdd3c10b2fb1bd069a1c9562bc8e257687a7dafc7f0add',
        'fr': '03e09c9eff3857288df24d820d70d036147a24425a8b33eb50c9ec4b2ea58d12',
        'ga': '6215c74736d63fc80408e337e2c40d0185f17db8f4ad3ce3813b4a6eefaf54f0',
        'hr': 'e9c65009159a11a0a2d1f455ef746f077b3040ac18e5a96d421d2c85cf43c333',
        'hu': '5196319ccca2cf32a1dd1ed04818eaa81659db4fc4c02fd28e52dd076f457df7',
        'it': '66ff4a28d9f8b76f0fe8381a999dd2c31bf93cb014b2d39a2bc24e6bad328103',
        'lt': 'd5ab95be8ee91c034899584d2cca0fa5247603b11a48df95539abe093ec3c16f',
        'lv': '8114bafa64b4fbefbcd8b95e79855a1950befb58eb23898ee5185b475e28a446',
        'mt': '72aad5c8a1d8757436c23ada71100096bc065de77b77a4e72c71b55407929db3',
        'nl': '6d11749854de23625354e30782ade9e4f67e0ba25fe37b72f3fd7b03d1fe7b49',
        'pl': 'bf49fb7641185f728154829a8efe79412734afb757c9b6d4c1296bd648de8df5',
        'pt': 'f8a04f76cc2cea5b61e981fa9f7031692ddf6d02e81513b3f562ae75da641cc2',
        'ro': 'de4ff5327c20cd53632e7d18b513dfc0e25390e8d4cf192982f6cc66ba572f3a',
        'sk': '905c920ccea90456a2cdb97fae843cc1fe5549319127f7ce5abcf07f4f03c910',
        'sl': 'f37cc0b2f25a344945eb3e6e5886e3d4cf287eb8ad6d6ac09eaad9fae91aca88',
        'sv': '022dda1e3f0dab9b6de837548c062e85414fb7f79c0da8bf6e851f88e3bb0d0a',
    },
};
