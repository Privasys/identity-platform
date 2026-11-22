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
    version: 'c9280ff793738613',
    digests: {
        'bg': 'b5537d101bba60febd38f60aaa7aa858d525ea5770614c71c29eb47a5794abb5',
        'cs': '47f50f1d3044d529c9c88141e0f6cbc08319dded94ec42fa8495f1853a4f048c',
        'cy': 'f885a360518b0fdee62d23caf2688b859f805f3e54c435e2b41bc5128e1be59b',
        'da': 'c6ebe664586e7552fd12d5239a5f54c551fbab0f568cfeb01e5c4b369cd09010',
        'de': '958ed37af242ae8c3ea63200bca424704c6a045cc6e7e71d31bd8a3221a3a4b1',
        'el': '8288143aa7aded7700d9e7f3c0132ed1639300c61759ae5df2192cb0b4bab3c9',
        'es': '7a5ea4c0ce5806fa97d4bee102e466c51784f34d5dfb332442fc20c85cd85674',
        'et': '85175ee4f625ff1c2b3f811dd61e3e6ea94a20fc3f1655c86a367c2c6e1e7058',
        'fi': 'daa8457df127fb079cef99b24b7540df999e78f6965268be827d285495322d6e',
        'fr': '26a7408c90806ce508e807704f7ba8fd40533dedf030d1ca8af23e0ec979debc',
        'ga': 'a2ab3b4e5f35827085ae6511d57e51427fef8bd9ae3efa78feb7c23490f1943d',
        'hr': '498fb30d1776b947a093536f4e2f7c8f4a5ced1267d7ac70b909106af3807f20',
        'hu': '685b5a20a5e6ec65f7fe1a50eb081b0293505d3020070f28a083a18f90eafc7e',
        'it': '61322cd29b2d15043389396d16bafadb6967b08817fbae61b4341d5735f2f65c',
        'lt': '35e5390ee461846949f0477aae0b9cc11bded1b9e6508f684ac4e37d9290ec53',
        'lv': '2277602e6dc2307e5dd6827ce8b2a997b1d9a5630625bf6103f5a909f2b6ddb7',
        'mt': 'c90f9cfb171c3be5f45bf9cdfcd0f37d67d00bb72f1bdc9d46f52905063ce8af',
        'nl': '7a97bce3323587bb1ba2f2ffa849dee57df37a110e350fe7eacf898095dd6d3d',
        'pl': '577c688f33657659847c296983a025b2f434bfb3a871ce7439a76ab53013af52',
        'pt': 'cf823763bb4f1216f807209c5667af4ab773298a4805af2dbb4e394edf3c3219',
        'ro': '8b8d9cd9fcd69e413fe055558573a4c2cec19a69ce480ef415fdb7384139d3a2',
        'sk': 'e5781924b10179007a7de189c41d54ff74d430ff686ab6842fbce4d6d3827cd3',
        'sl': '16a1ce891fb87d88dc1123a3cad778a412cc0fcaa75e72003845bdec00e404c8',
        'sv': '11a1da22d94ee4a10c97558ea611f21fe262087d295e593cc6ab8a387e6ba574',
    },
};
