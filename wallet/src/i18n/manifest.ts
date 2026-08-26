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
    version: '7fbe25d7f495420e',
    digests: {
        'bg': '371e52f3489dc656edbc120193925356569cf191df04bb76ea0cb86f9d76a48d',
        'cs': '6aee693ab45108d863e6caba491d1e0a260174655b744b468e3b17648ca1fc80',
        'cy': 'df4e9fc92ff83d3d9f38dada0df5f2b15b4c7a51f8f92aac3eef3030a8f1fa55',
        'da': '51709f1faacd0638931c439cb202d0ac89e4bdae9736de4bc965b32952eb9af5',
        'de': 'a35e9800a7d40f88bafab56848075f170739a699c0ee4e1761070a1e53e0271c',
        'el': '863424882221123ade5b95f07b92bc7ccb356790134e915c27ddd1a0ab58c215',
        'es': 'cfc9edbe1f6db413f7b37861684723f1079138c18079549c533f870a134584da',
        'et': '91dc588c892deaab801c82558241baef2a367990941a0a34527a2b69e4d347ec',
        'fi': 'a059d155e4f934ca003b706a556c572f4d5f0a3886cf2f7079e56814333ce774',
        'fr': '0fb0bbe541b06df2d45e122ea394053879f17e93dc20c938dcb8a14ae43f78f1',
        'ga': 'e4f1cadb34c34450f0641585c762d278e3994dddc394b88e734e1e5dccdda4f8',
        'hr': '974809090060e58ea5da959e39927406fd512780d0ea359e500e4f47206083a2',
        'hu': '711e4397eb4b0a2d47436e58ef755e51ad6ede5176d6ccf6042f8588b288bf7c',
        'it': '75fc3d5d641c4fe5f3a78a6a541d5694c5d638db96eca3aa6dff1bc7774f2856',
        'lt': 'b5f3ab8180fc1ffea8eb064bf399b5c893ee1c87e0bcd51810132a60d47bf3f4',
        'lv': 'ce08a9a084c4516005cf292f67d41ce34540339567f0b530cf2f6b1f8e5ef631',
        'mt': '97f8254e1eccd60e1322d89ec805a6d3239b12e476fbb204ff1bb296da76e5f5',
        'nl': '0a8f7b7e091fe74e36a6e37abc7880d40484ddeefbb8e21f70d7c353a61ec575',
        'pl': '90c7956fee666b91f7cf151c8f085d88739563d70797ea4202b31a904250c51c',
        'pt': '7d069b5399ac37034350fbaf2a10f7c35646446afe11a8e669633718120e76f6',
        'ro': '959de5b64aaa91b94b6540ea139f9c3607c8c70bd9c2b16b74f65de40a44c33e',
        'sk': '53f80920ecd83e5eccec1974549413f6fe9bfa28a49c2ef56b40907a8419cf99',
        'sl': 'a2aa7d5901725a2eafb4bc4d6f2c150c0e24476678725c390592e0cf12c118a4',
        'sv': 'c9dfa5e783075f283be3947409d787e14fe7997dcc85705e3a45f8466b1544af',
    },
};
