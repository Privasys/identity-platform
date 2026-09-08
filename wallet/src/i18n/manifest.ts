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
    version: 'eec6ffbe47c74b47',
    digests: {
        'bg': 'b8da57061761f8d828df87170ca345c8b041d6d01e38cebcd5a3ff77907e9467',
        'cs': '9d44748dda3d798d8cc92f786a9ad93d0ee5fa6970fbede1f7c2ce0fdd443696',
        'cy': '246043bf8d4062a102daaeb0a08dc684645376e049319606c805a2df762c881f',
        'da': '1c4948a69db9fbbad25768cfc7b1bf3e9c5d640825f1b0c7cb863fc0fddf0722',
        'de': 'd6c9ed45e53d8e77b2a69ed1ad1aaa670b717b9bbc0abba41e09e4336ec394fd',
        'el': '5a0e9b32b93124b5f2b6287a2b690467821b2c54dd818d47a56834e1cc5ac8da',
        'es': '20122ac008a6ca05014334ea67bd48f26fac59f1f503bafe0828d31ed4447434',
        'et': '51fb5d6423e9afd929bc6659b26c396d52b75fc181fd3be34685acc76e6abedf',
        'fi': '7dcc7e649637519e31cb021283b0f85dd4765acd1a541174c85a619c9abbfb78',
        'fr': '692d0f617665556423c0de8308b16ceae24de0d46c7d1dc2056bf525333ba796',
        'ga': '9f2bc6c0b1764950558f0f88624414250ef81bf20ac6cee0475c36da9091000e',
        'hr': '7da5306b5ff3f7bf3b4461988fcecd6fec11c4f78603f313af8cb4a7949d70cc',
        'hu': 'd2e9b60c2181213b38cff5f6c8623fc7e211dc1a95899b62b4e7ec8c1631ce57',
        'it': '6bcdfccec91caec47b56690221c40a1905dba16c784562d614f33a6d557580d2',
        'lt': '61f9541ea47e54e1abbda524ad8c19b8ee9bdffb66838866ef884f606e9827b9',
        'lv': '8fd258760585ac888b15d67ed199e645079f0468a232cc84274e6079a86ec9d9',
        'mt': '9ed916e7947b95a0cb6373bd74251735d35a536ba9149cf6d33c34abac362d42',
        'nl': '1572d211e2d36161d854d59e7d058e2d9f3a9411fd7e814845c8d5ce9f056d90',
        'pl': '64d813653f22f0b46b41fa0e2ba9ea0561929a4bddc51df36adc72fd21680a71',
        'pt': '12921950452ee64e9e8bdc5f25994b7035d119a5227945cd72c01d2ddf8e71fe',
        'ro': '1271ecdbead4f4f8b29caede01d3ab7d6259f55ab08d7f8e344490e0178fd39f',
        'sk': 'aabb6d7ca9337de72ba8f50d3a5f3ee811bb99ce8fb93790751a93c807c31b8c',
        'sl': 'cd25180c718a1b6faa040800ed77d5db2d3a37f5d8a9d9be2e36b3bb8478c18e',
        'sv': 'bc71570d2d0964f33a06b7ff60329ffae14ac602e4e4a808e48a0340194831a0',
    },
};
