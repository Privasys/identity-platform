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
    version: '7da9d60c27cd7e37',
    digests: {
        'bg': '6dae1022c4027cbaf5fe6b622fe5191e2ad8c5588e6b9b61be5247ae4d62929e',
        'cs': 'e6ec74158df912b4f0becf2cba5e52b0c1ccedb626551b98f9d8c4dc2abb4965',
        'cy': '6658fbad970aecef8327f364dd62b7cdf4c03ae3ebf341f77c2f3c1a43890024',
        'da': '5dc969d12a96df77408f3948b0bb3a5b3be6b5df708c225c4a41a633761e704a',
        'de': '23f0df8c77e4b91815bff7955c2ffe8c92e325886e693250c9e27466654fdd97',
        'el': '4d68e71a7bdcbf49d6acdf9b69c0ec27c0dad1677899dd99882ec383d86c97d9',
        'es': 'ffc87bcbf02448899a97ab89e816bf6e14e7149e4890f1322dbac2769dcd6229',
        'et': '1ca8dbedbe2f1c2ecf70db595748fc0dc39dfcaee21bad27315eaec1b7e5138b',
        'fi': '6df721019988f6a0ae013d4aaf17de35a1132b7bd7ceaf408116c867dc65b757',
        'fr': '259ba05b79634b4b8990d0280577f2fd04409b02dc241570090d28e939c7307d',
        'ga': '84865f3a67eb4e82e168735a776c6067f4a48c2db348c4bfd643f03035a58b76',
        'hr': '7e026b9b7726e96ee6f489a83cf67704ba45290620d9d73535a7979fbec0cd94',
        'hu': '4c7f25063c7e4d028e9cfea3957053654763afa7b4c0d374564bf48b7386c2e4',
        'it': '75ea00d82d830384a145b2380569f08cc17ed72f24de0f695aed9f616564ad2d',
        'lt': '140390f860f29d7b0f83972e4df8bbf98deaa14e4acc5cb26a4555966085aa90',
        'lv': 'af1566f44b6a2d7bbfab3c441c8f018fd2f3f407da76e062aa319fce9ae7d573',
        'mt': '64557b4d89c71646cac41f757f912f498349705d6f886f0e7afe3ecd8c0ec7da',
        'nl': '31377f1a0a46867ac5adcb34ff33c3412bd76bdf8d317983376b1052431c95dd',
        'pl': '1b2ea3f179e5bda478ab872bf8298d38d82be819915921e37306c968535a9aef',
        'pt': '0f08e3fbab8a38b0fd12a1426e4b750e9331ca662d5714e904588fc20b099550',
        'ro': '646c3822ae78a563651904616869da7d71a0666d5fa07bd4a0a99a8a63fbc2d2',
        'sk': '4397bed9d9989522330186ed34bb5b13aab393019366ae7099609db04a8256a7',
        'sl': '065e953c52e86979ebdc5587788bece96941753ec599424b34feca9ee6746b6c',
        'sv': 'ac02685fcd1bbfb8a07b2d7866a3e5cf01e1d9cb017a9121a8ac1b68299df075',
    },
};
