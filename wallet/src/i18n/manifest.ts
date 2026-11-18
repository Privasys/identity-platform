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
    version: 'eab12e76e7b043af',
    digests: {
        'bg': '955459a6a14c866bc2e58a670b319f5b9e02302813dfca5736fb993100ddfa19',
        'cs': '792e77bb8db757a35c4f728f3090b1e523e559fd01df81174301e490c3125f4c',
        'cy': '4be612d40cb4d8bba41b05852e50afdd630b7146b2c6641984b072b0ac5463cd',
        'da': '25c0083cbc35c62fe6d5c29ca5e9730b67f06f46804b71d5586af5270d5c5b6a',
        'de': 'cd28d6bfdfbe2dc0cd267b247ab44c63dee90483d5836a6817ddce1633ad743b',
        'el': 'c8e01fd86411432dafc8f774f781c8a13d66743ba7b72f48ac973ab62f330a42',
        'es': '9c92a809991382bc283bce50e6ad900c6247a6212e8bb4c7a2a33fae4028d76e',
        'et': 'da4f671bf7d79b171e407e6b9bed46a035aece68f9a3279576711eb1c601e74e',
        'fi': 'c07fbdef2a45d369d085c3faa22ac800fbe797187c126e808943fbee230dcf01',
        'fr': 'de7192a6c0bc71443c63b5ab1e79577a2c66d6878b175f8a0a51fd98262447f6',
        'ga': '2a8e4767a7e667ed1f1092e3202f43dad825c822effec8ff5fca03fe13bb2a87',
        'hr': '2392eb8af603cba9cd19522a3ad7873d84e9c3f0f020e021942a278649dd543d',
        'hu': '18282c4cfd6fbbd06bebfa69f3b7cae012dad69726111f012046f89869986348',
        'it': 'de792b8e8efea0a8ca30f5c4d7432c8acd8b736f974d0ef6ffe104c2681df3bd',
        'lt': 'bd28bbf3d729f0429c57382668812d26b3fb85716b7b744c7bfd0084384086b6',
        'lv': '4f63fe9c6362bf13d923882d22d638c599c83f866d22fec7e1652cc8ad23c74e',
        'mt': 'ac004c3d4ace7b1c619b0f4fa614508a427fa5e9cf50315e83b3945fc5df52b3',
        'nl': '2be3ad7b1f33b0008cd0ce6031bee469311714843f63ff79b08881336acae394',
        'pl': '86df639f8332a9fc318542681f7ffa2b151e4d64dee2b34c476caa3d293cd8f4',
        'pt': '7e8753b6369ae4caaac5d449712122c90a097e193854c1659b464377d085e84b',
        'ro': '1ddbd23b1ae9ed9f01afb63359c2511d7a1fdeab8df46311d666513ef7e36d9b',
        'sk': 'c6fe058e6c435fbf4990b0146db8e7f0614a14b8bb10b6d07a8dbc41ad6b9425',
        'sl': 'ebb9e53d68c965876da9a3a0e6f550b6538fd271380d6ae0254993c81965ae34',
        'sv': '0da20846506036c73f0f2313eddf1bf276c55a1bccfb63fd2f23beef9f471b48',
    },
};
