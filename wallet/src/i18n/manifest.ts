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
    version: 'a96bf0949b1fe73d',
    digests: {
        'bg': '4b992e3a87e7ae3353fe984f4515233f7ab50add8085346f8083d7a4822f7710',
        'cs': 'c2add22f7a5da5a91823f07a2c2e014e50aa0f5d9ad39a17f0767cf5ed084157',
        'cy': '19b31340233e8bf59206aba387e041ff0da72b8608ee4831de73b284f0d6ed8f',
        'da': 'ad054e0666f4d68283d1e10e0b3e3a853cc5afc078ffa9028a58f3e82f031965',
        'de': '5911de91da1a8358517807e2e30bef38cc31bf269f2bc9bb6857c3f901706d25',
        'el': '46d956ec905eb97c2293b070f0afb335452be55441c1866105f484b93d670d6e',
        'es': 'f671e2e5cff9b841ca802ba1f0f4333b6505a99b0f90e2a26efccb2a7fdebc9a',
        'et': 'ff2eacf3bb9b4af1dc694ed546f9b1b9396db1b1554aa228b2bc53ab89f070aa',
        'fi': 'ac54d31e5b56db7385229baec5ca60d5ce1a836fb4bf371dfe62f83e96fea5a9',
        'fr': 'c15605f6884440e942f7fa11fa08598bd0dc10f2f848f1911d072a766fc817e4',
        'ga': '179938fbf142da2a0df240ceb002e909f3656961337eba22997f64a4113a5d30',
        'hr': '84fe1ba54d3c3e9bb0558e01aaf85237dc6b7d0773e42d327c8519dfeb44c502',
        'hu': 'ec7b25f212db966f0b79e6d4dfb828c434c600d18ca00d5c857cb40a20c68bc8',
        'it': 'e640283766352ae87d5be8a1f918d37b0f3e36804c92e9002a391c867c50f717',
        'lt': '9a886bef5be30e8e5f6fb74b6b9d32e8e52458cb9ba09c400ee778e98d0f7745',
        'lv': '03c35a8640657fd21e9ba5f76e974c30bc7bfe92c1703a14e4f8ae5ef90d0221',
        'mt': '09c03b44d999d4903f194e3066558e2a6b4a2faa8bbbf95ba79b583201dc4424',
        'nl': '27ee4a779e79214e40f44ccb45c92697435eaebc8d86717a4731a2692c3ea1dc',
        'pl': '096cb1063fcb9a70283ccd35adeeaa53a8fc992362b694680ae8e21de50b7bfb',
        'pt': '627b46f98541b0f63ec7d1ec81ef2540f4957c05e294f4b2d8e8559981c35da4',
        'ro': '3e5ebfcee152bb3ff1b31beb33461dbc1c41d382085c454c3d6a843fbdbdee67',
        'sk': '52b438d24e8f3df2d263586f8179234bcd13fc06457f256ad3018604c9544552',
        'sl': '70f6bbd0406a46ce83599f7141d6e4f5dce2657c9bc7a69ff1abbb948338d697',
        'sv': 'c183c5a120d8b9c90de038075d82faaa1986c6ea5890a50c79fde2e378d65cd6',
    },
};
