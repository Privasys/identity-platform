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
    version: 'a28ebad7df2e5226',
    digests: {
        'bg': '7d0ae4d4d0d03907a9d4a89ff3eb390e70768d9f6f32d7b50b3cecb7ce26313c',
        'cs': '3bbdaf035520fdcecf7f5df2548859bb0cfb06adbd5163b485ebaceb5171d4f5',
        'cy': '0cd11d35a4efdcdc1e572279b575a78d5bdeac701b95bc2604f1cf8400cd55c4',
        'da': '602a6c888cfb76ed451a21a6d20d3cdf66022627f5c5e44f0c46f9b9ac5c4e52',
        'de': '4190878b77209c40e6d8a8e0ffe312d6f9935e872c81e50a6fd87df822eab4fb',
        'el': '56d55a064b2f45e3c6d9faa6cfd266556c2676fb899891117ec9a718094993e1',
        'es': 'eb3e806e110c7c49c9037b9426deb289ad259a7c82f49836cdb339abb2455452',
        'et': 'af4e0d58b40eee9ccc10e3e9b886be9e0ee2a1e4a525cb5dc1f637b4ec496509',
        'fi': '4d1932f6ce1282106bf1eb1d0bd44dba890c95a4d91686c0c1127cc64f2b8d6b',
        'fr': '12b3f2a01b8c93f72799e28e262a185c018e786cd3fce90f6f709850fc255c43',
        'ga': '8cea90c86693cdc643c17db023d365cb1d769664d0353d4ac2a71bec2aedc9a9',
        'hr': '48dba576d730ca179df29c0e1f21aecb1663f7c6f205106a1386973c4dd472c3',
        'hu': '39b7db8c6bc187223e31007cd74d03752b1a21e616c828785a64a90a47c56af9',
        'it': 'ac77b0d572ef7096294669adf49b7f5295a160f8c42abace9ed9fbb2fa97ffd6',
        'lt': 'e3699750e83ed381d7f0102baa581710dfad6152e82f561c956fb439d593be0b',
        'lv': '2fa4183d736de52a5f91e4fb53ba7e2bb23ec225a8f99e3a80b7179cc4069cec',
        'mt': '880d82dc848a1bb0f780d22ebf66989555afbad4ef333a634df4427df3ce83f8',
        'nl': '0b94a50316ffd68a2145b43430f42f8a7dda4a6052f03482fbbdb2f8251d8ee2',
        'pl': 'cdc3b7aba1b87ac0b186150827655d219f8497173b40a0f208e60e6946509e74',
        'pt': '723a9c4918102e709e0dad731247a409245f6b4edc2ef2704a1b2be67e949cda',
        'ro': '4495db59d18ecededc9c5a04bb3c5795c8ba68aca661fb697ac89c561080d8ce',
        'sk': 'a10d8a4f702a67fa0bbde57f7d91461bdbe26adb8ac60f4fc9842ac0aa7b9741',
        'sl': '0565b8307a90ffc31f1c267afa7b4a879987756d4a56f4fa6191bfaa4bea42e2',
        'sv': '97245044c7d252f9127e2c093e5f70f7b752d050d2e6deefc1389807f9d86600',
    },
};
