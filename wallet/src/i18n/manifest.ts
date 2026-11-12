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
    version: '20102af26108668c',
    digests: {
        'bg': '6918911777b1690a1ff61e8ab365c2a3344124bb43998eb1f6f36b57a1ca1115',
        'cs': '5060588ef54b6ae9935589412685c4dfeee7a379956c2b33eb15d0c64cbfead8',
        'cy': 'ab986bcf10d8e6fc8b54eb2800d78fd5010902cef978ec6076daa7a601d31e4d',
        'da': 'a7b54666886ef6d9057888b7e2feb479c78f4d0170d21bdb447c1b79872b97b6',
        'de': 'af4560bef4c1d3e19e6996de9eb0d39c619d73930dc509cecd99fe4731f8d194',
        'el': '24deea90c8a9ba19259e52a57ece2da6c81faf5fa126662e73bf415f9a38ae3e',
        'es': 'db8fba0e2103d3a4512f736dd09d833b40c04107c52f8fa6bf9834c7c3f55ff8',
        'et': '41ce9deccbf3911334a4a2acb7148f6c7ceec4c40b66a55256bc339de0503fad',
        'fi': 'b8a59d8af8151e1d60f4b4899e65aa0494b56b75a1613adf7c329add5717fe4a',
        'fr': '2531d9fddf56ed6a47241b9fb1c55c69032fdc630428f38fe78bf1e86b2832b5',
        'ga': '0907a1cafc5ef10158870d784c98a768e799ae69a5d368a9eefbb008070f2c52',
        'hr': '5f6338570977d9780d6a21e9ba28c3a16edaca40cc1573937330701e400cebdc',
        'hu': 'eadf023a9d71bb4fd9cf8ee28e43398c1a22a7571e10562d98501ff62b21ea9b',
        'it': '83bf24814523d47649cbbe43ca444f8fcc68f58925c850d5d88b9e2faa4963ba',
        'lt': '393df40dd99c079ee9b5a3abcc9b032c85678fb8e49479af505e10bac48dbd00',
        'lv': 'f0d028b21702fd22343e3b108c0028e541914328acdda73cc01261fc609384da',
        'mt': '93031182d875ebab2d27bd609936fa002a025f30332337737d716719acb812c6',
        'nl': '458a0e0aaf4987a64a8588385e28b97c16c734182964e48c762a2494cacafeb1',
        'pl': '2277da1e5daa03a7a955ecfd7dc965f79151c7b9d8e71ee1a0375d58c2697ad5',
        'pt': 'f21bb4e3d48c4e6c0365c0b7c46652cc9c59d809e643037ec5265fee597ea5e3',
        'ro': 'c9b1cef34279f82749471c900007f44e67b3feadd9d3c05bcd45ca87b52cfd36',
        'sk': '382ab59a3d6fc35ef09774e143a49725db8046fde49d85bfd13f10580691cf4c',
        'sl': '72c1b825f365b58eff20db0a3696835449c6ace1273bb36fde8ca6bd26faba7e',
        'sv': '195b8af138a7911511f27d5a10c990b382cd29625d7e5edd51b36300b807ab45',
    },
};
