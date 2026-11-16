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
    version: 'c77d43e85868ef6d',
    digests: {
        'bg': '0f5872c23fb73e934c6de73cc265b33dba2d3734b46b34bba9cf718627cbed89',
        'cs': 'abd8b654e8b4c987c94285a245de821d090a07ef4fd7cf19a7ef11b12b970982',
        'cy': 'bb3cbcf3f24388bbd7f779423bb30c1ae8f9691e1df86fb0fedfa1b356cca9bd',
        'da': 'd0e0fec16f6b379778097356d485756486631ae8d1b9d5c80315ae51509296f0',
        'de': '3e2511d4f7947b9f9cf9f23088d701049d64b93d313f798df375b08ae5ed37b3',
        'el': '83697467c4bc164f586571a0049cb39219669ba3b3b4f0fa7b3511f15d6b6ec5',
        'es': 'd3fef7627a221190f8abb982ad766939a9bbf92256c43dc75685c7e9259a7e39',
        'et': 'c87bc5b8fd68e4ee5ecd8f10f9a77bdfec2f1488ab8fb3b9434d34dbf434483e',
        'fi': 'c6d4021135d4bcc2e45acc1c0b2097bfdda96a62f1e308544805bd8031ee19f9',
        'fr': 'a25b6d9d136d156ad2673fb3dd198ce8f2d87a68b52ef5fe88880c9b8c5632d3',
        'ga': '610c42694dd505e3f46c34c69147462404c8e4804f7ba6935441ab74e7a2a723',
        'hr': 'c201d04217915c89235a3389437b9e692ccac81f4ef50c9d3b81659c60472271',
        'hu': '5fe614bbe19c658215b5264207a751fd91a4a1705e3d11669acb059af643c36e',
        'it': '02e82d189ac09d80e65de314447c2ad0169b33dd56bb0eb69dde4515aafb6f10',
        'lt': 'e2dca668091d9e8d3ca90dc3662ad37acf904e1d396ebfa914330981db5e1f53',
        'lv': 'e4df156a5560d654e7bbf6d93de6747d654ec65fd07cfd361f756792f8faac46',
        'mt': '0ed3466de43351291d97521e18adb4900a01223d666dd357d47c9e9294696fd5',
        'nl': '59ae75bd2bc283f94879c50ec72cd753b4bd3a6676d3aedfab20a74d32444538',
        'pl': '8914f88af0bd0e90ad9f70dd8951edaf4f642ae10eba6cad07b4514f7de85fc8',
        'pt': '8f0ba155502173ddba1ff9a05423dd55c206cb40d136099d44149d8a3e6926bb',
        'ro': '81f1fcb3d1fd879023fbe92320af248f4d439b935df6b188a60205f181f71083',
        'sk': '9a2b1ebb26d6854241061c3336377df7e6d799b0c6f6abcf6f3b042868b97022',
        'sl': '2713b279b2221b351a73192cd5087e5d6b4b430e61bd96fb2cb2705b87254912',
        'sv': 'd97d9ba5d521f3593d17646c5635c73122755bfac1edf77438edb1071147d2db',
    },
};
