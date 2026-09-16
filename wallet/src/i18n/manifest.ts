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
    version: 'ae32d44b967b69e7',
    digests: {
        'bg': 'a49ec2506db7d0fac35bb038c49e19d92ee4804259ac2b315ee1639071f1412d',
        'cs': '0f7bdec7ce14ca9d10fecea371dc7667756c52a16872319cba1443796b954921',
        'cy': '48f434b389b5b6ee8188b6b7c0cda959f9e352e1986f38bcc4465163e48f1586',
        'da': 'f0c66e9bbf336cfeb21768e0fdc7f6c793ea43e1adcb1a016f9daed8cbb4a560',
        'de': '0b6bcf2c65dd06e70ebfb4569dc2061ff52ace6dbab59a2e3db7530851d5baf9',
        'el': 'dee802d4ca5c0b5a98a518bb696daba6b7caf408a651d71624ac7900ed4a3c04',
        'es': '3f909dfa1fd23a8bd2afc4ef8423238844181e31ec3596f0c927f82933c2cc87',
        'et': '8b247127bae202e929078b88bc0c144e6c60c68fe9786d5aaad034c1c9dd41a9',
        'fi': '19a83803fe4ccb1e7c8d90f3f575ada0d3bb0ba140ce4c9603268be567890b47',
        'fr': 'b05c90f22dca449e496f542d1d00d81a8de013812ae0e3f8fec0e51017ad4547',
        'ga': '78b85b24ad79f6204a57a48109f0d5417f4b6f1160a893f1f369c1e241eec09e',
        'hr': '695f676f905e94a1302bc4396e0d3d05fd2eb170590af59be4c8784bd33c1fc1',
        'hu': '23894cfa8b3a61cf674eec60e5fa9b7e6939e64b230307ebfbd60d2b8f5e2e91',
        'it': '0284f307398757ec8ebaebe8ab6dbfe4d887fce63b3600435d5cebbb7bfff09c',
        'lt': '8cb4d145334ecb80cba6137de4355baf220cf3c2073181c5459fe870c333db5c',
        'lv': 'ed4b5f7296a9032c6196c6c3f784b64c55ca329737fb63aeacab97fb606990eb',
        'mt': 'cc441bb2d1529eb2c187e7335bb8dbd233b209bf3a00e7462e0ded8ea608f617',
        'nl': '2028de074bd3101e696019d37b5e93eb4c4a22a680e92a2ca036ef4484734257',
        'pl': 'e5a5c6bdc7919b78145afe0b565794fab216f044f6dbf0942cd450786ba47d54',
        'pt': '82f673a8953a14296ec640e534acb2e00d6382d82b7025fda1bb5702d67f4c6f',
        'ro': 'b9dc7ff99843bd8cfd29f8a7f349e2341b1cfc62b85158600d60e9ee5e3f8e53',
        'sk': '8d7a4877860f08313589790ae6cbfcafdc8f351248456437a5391500fe3d7942',
        'sl': 'ebbc79298e8c206240889182c3059770da7d859a51e9fb244eb04d6e330c8b52',
        'sv': '9ead34c97e95e2b380c5b19c750f4a290a90db8e7b22bc704bfdf5cff5ea9a35',
    },
};
