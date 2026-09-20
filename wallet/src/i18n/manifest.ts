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
    version: '9215937612e142b6',
    digests: {
        'bg': 'd6419bcb8cbd5b28d78622c3f8268b0ae404fe02f7e94b2a4d09be889abb44ec',
        'cs': '8f067c464171a7304e7b07cf8997ce2e803f3f1c6740dae18a4b114b57853196',
        'cy': '2a456e6694096f86f1e9ae8876cff4c1cf180ef36dcf81f12e2183ee346d360e',
        'da': '53a67947cb3346fa72357c06f7ce7832de479f261dd8963b6718019fdcbc083b',
        'de': '75abc189c5e5c8f0a1064f2070f29fe0595a69420288e5c99914a58732942abe',
        'el': '44d52c5e59995116f8ca476dbd2fa269d9a1a70893d222c6ea6570f0012ac931',
        'es': 'c5d2f3c4ced7763e96143fb2796dcb59b865950608cb2f23a460c8c361fd0ac9',
        'et': '478e993f8c0b8192691c486d4bf93d2c519eb5abdce601f8f7976fbe30bf603a',
        'fi': '89390eb71fa2a02009e280f75ffcc510907b4225de050a4a2dae27327970ef19',
        'fr': 'c02d575b996622a6937b18184e71098151a2847723e9da513040b884572b9aa3',
        'ga': '8da08d3b858469c4d104e9640e3eccd824d79d6d855a117690ee6942a2fdf964',
        'hr': '0c7865fea7cfdc352556d4201a316a8882ff35ff40eb564da3f8638131dca491',
        'hu': 'ed0b8affef2a2bc744bc85018802f471cd563b8d2aff093fee8af8be8c43bed6',
        'it': '86f89e6c4b65b0b8d4cda018f8279385e964cbc5608fbe7d67246fa199d00c9e',
        'lt': '88201d811739e1e95c52284b47c47d66851ed7fae16639964770adcd9f55d6ae',
        'lv': 'f706e789cfd622ca7932ccab7ee38b16a14a589598c1774d277a2ce2c9bc28af',
        'mt': 'ff96650c8a2ef4db9ef2565d03cad8752aa389571ebad76c2a5e3565d801c90b',
        'nl': '628d8a543bfa0ca005c535e4c76e45c09b91699d67ab47f62e4980d1ecf1324a',
        'pl': '465b2d8b6af6040a92a70aade186bd4e88fc0d39559b4203f6880e75a7e66276',
        'pt': '7c8e160c1f731a79d516264595aa4f89dffabe6601a9ddad8213f08117dafc4d',
        'ro': '2a8bfef5b54fa67b9e1fa066c0a17c3b9652f8c6827088866adf7351914ee3d2',
        'sk': 'fa6a80c9889e7e2652a2ebc46728fab5957f1a0dd29fc06ce4a8803bfb05a250',
        'sl': 'b24d69d9735a86b160eecc76f9f7916913d88d1142eb37b22ebc74f368281cbf',
        'sv': '82dfd59c70d91228e97b7ad28b1e5a03c7512b59b8c891da1fdaba72a3721406',
    },
};
