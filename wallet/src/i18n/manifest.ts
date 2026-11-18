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
    version: 'e2bafa4424b63b5d',
    digests: {
        'bg': 'f4922c1781c420fa057ec13bb31284bcbba89e5ea5ef5fcb12217f29486bf8a7',
        'cs': '3349c4cbf075f6ad3be46be7e38f14539bb958c9f2f4a1a975946ec3eb37178c',
        'cy': '0e7a4a5da10178c6da97be546615f829c5b7bd1741aab8ee1fe6782bdaa9f556',
        'da': '170e9b251a6fd2a99d97db5a35cfb79b82df9738a54f098c5dbfe3ad6938ce64',
        'de': '6e00e5d81318412654ea0f6c53263e63f3becec974fc95403c056478998e03c1',
        'el': '7ef945cc80953b497f3f9953abcfb36fed2bee99f7a1a3ef8629cf6e836f4937',
        'es': 'a70b3bb5f59b804f3334edb25b15f8682317aa33ccdaf8e211cea57045d999bf',
        'et': '8b00fb013f27927474eea7df2bcedefde5fa863bce4e815d39f9ebc9f267b799',
        'fi': 'ce019a89b363f584ac71c933243242c3568ed3168fd466d57a06a5047f0c2851',
        'fr': '98ce0e26049602dc044c976926f7bba81d97bc3c8caab1a62b315f6ecad0c37e',
        'ga': '622c8f32bb790a628d67fb1a5860a711915292a6f75a78fec62d8e87fbe1a22a',
        'hr': '1959a5084b6142fa176cd95aeb82098ee00fbaa6bacd03e186e7f690bd27b90f',
        'hu': '93786143f21e6073fe5aedd6febaef17eb4ff6a500f560d996e5c01ee73d3ece',
        'it': '662cb7ccbc3607e0958cac9bc5f2a5e6bc93b5f438b93131925d55f9836e7254',
        'lt': '83c3f4a4c127317dd04cd0d88beb23e28c0c6a4467994071d3f8179f93fd3864',
        'lv': 'f5a85fa9544c3711edc2875d0b3e0c232163071739e0100667924ecf7cdfbd29',
        'mt': 'c73acf598a929910327c09220a7dfa264ddab200706f54a1a611abf1945c7b37',
        'nl': '756eb632d5554b68a228e98c8be69077fdf8a8fe61e14b4678427cc0c9a93ed4',
        'pl': '5e1034d3203af815e385dc089f6571132aeb02ffd706a32378180a907ee45177',
        'pt': 'f5a640b747f266e82993710e19783d6548a93c4b4f178b00345e9176b7382db3',
        'ro': '79c4fe71f67e93efc90cdf296626562920fb971e81890f8b848ad1ba54717e1c',
        'sk': '7b1453b7473b46cb7df08c8d7ccccbb473c24310cf6dd03bc9ba6cfb85655159',
        'sl': 'd12ec7d6e2afc661d3d708f05f8ec2320fe611984bde1a1046511d7053951f15',
        'sv': '100b09101c305c41664223a36e68e256b1737df7faa3a7dcfac97c2f2187c71c',
    },
};
