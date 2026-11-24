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
    version: '73c76b641cd5cdb5',
    digests: {
        'bg': 'b875b36b046c677e89e50f0d15d307182810c2ebaefae38a33fd61cfb36c70c3',
        'cs': '81e2c60300092b0b450c41beb82b9146f72da80465d41bb62630d68ab5dc279d',
        'cy': '3cb44e68e5f6f7b1670819cb41a1281ae889c6b20cd98ee0af69514c426c917d',
        'da': 'ae9318252019d8fcf1863bc8ee5ed3224062762b49c5c48feca96fb06d8cad63',
        'de': 'c956ab46a9758e06257dc9b38ad2d4e1dea571815a26298a11d9f2936b0f7aee',
        'el': 'c4ed89e52b07e8989a7222b81c72d0b330abe44667fecb58efd782ea6bbd164b',
        'es': '1589a636a78a2e0f5ad4ad01428402ba740f9f4d163349b30795ede1fa2db422',
        'et': 'fc3885dd57331d0ba7b370e0ce8f60217bc0530e429a43ab2ea09d29ba8d5a73',
        'fi': '67b50000a966e9dea172dd5ac896ad7be59148393e650509af52d7567c72701c',
        'fr': '7ae5633f66c2bc62931b0d6bf3e42408494e64064e66c2f8d46225d8970c1d70',
        'ga': 'c5bff38e13f74fc350f755f22a92bdeb4903f3b8bf265984dafe64710f8f6195',
        'hr': '426767882bad001f445eecfcc5ff3b47d768a1d28b068eb22d17979a0b1fdceb',
        'hu': 'ee2f214e8ae23a10737e459162f95e2151d1c15ce6eedd0dc38f92506efaed9d',
        'it': '4fdb0d19157adaaf5ce14e4dd9f178e016a765b5da664837aab20e760ece1611',
        'lt': 'ed7b46aa56f7c0804dbbc5d5269803e2c7afb7acf4e12ec0199f91e620718706',
        'lv': '9d13b63b9fb9e269bcd9ac8f5cd9542dd00363b49cb6dce52ca4bbcb58c91567',
        'mt': 'c861d8b6349609ae3628fe319afc53525ce8c8878a5f743b08ac43aecd254c7a',
        'nl': '4b842c856ce97e82c76aebf8f9660d0c669cac8a815ace65f3e1d051973f3600',
        'pl': '86bc448e5eb1110b79d9c341fe3e0269c2f4cb3bf34834daac1271fbedba318d',
        'pt': '960139959b6fb59c7d75728c8ea5ef78e6f13a6bb64bd39e180a3e485155dd96',
        'ro': '1a291b184cb41dd334f64e8d5c8d107e41e18445000f06e403a0ea9bd4c04a9b',
        'sk': '8b8f87f99d884ea5517aa4b14e08bea6c89db18ee6e9590af1a91f670079680d',
        'sl': '3747fdc877c7114edfd524acfc0f71b0e6b8756f4ba8c8429c57e13f30183490',
        'sv': '479cf925d77e3d8ded22e2b3a113ca4e1532b0f4f50d570f2de1eef5f6022043',
    },
};
