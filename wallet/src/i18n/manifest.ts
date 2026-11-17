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
    version: '402478637445fd9f',
    digests: {
        'bg': '06263b405bb7ec9aa4d8b0d411a5618266e79c90ce4bfd3db2b932b416241b6b',
        'cs': 'fa5f46f8831fba332adacbf93e82ca1c875a5312477d2d89adccd5c0def38601',
        'cy': '9e3b2d132c58733f8c6e3a5971ab712735ba51ed6ae8aa2d4dc78eff757b790c',
        'da': '07d3cf6f2cbfc9071cf4c0dd29b1a1296b907cfa921e94bf1797eaf302a33b19',
        'de': 'dbf329c1788d73f41fb1c2adbd03242767af6bb2901a917b6387b29b4db1e4e0',
        'el': '8109e2f0612487968da7caeaa322495d0eba60328654dd13e2ee0f984eb93139',
        'es': 'd28e5ddfb89cd9856fcb4929ca0cc3e406967164570fc6e5bbb5c31082bc2728',
        'et': '17acbdeaa2db7acdda1ed257e16747b2689838c4223aa976877698ab9c78ad80',
        'fi': '11880b285a959cbf60be0957046e6ab3b51be812b5a901f15f1c4c5e1419b2d5',
        'fr': 'f3f8026b5eae77e4d2c91fbf3ee7ddd5098ab4301980710272ebf30ca783b369',
        'ga': 'd5f691e9a5ade3ab5dc51a6f83138c4ff862a61e3e7c1b671766da9581eaa3bc',
        'hr': 'f841b7f55c027463b86ce4a1ee349b45e88399bc2e2690fb0be09e6188e71c27',
        'hu': '19c8f4fb4aad61083bb18b83fdf21d449f388902110d048786b5a2d3ab13c95e',
        'it': '64a7ae4d07069b0c75c1b4cccafc1cc2fd64e8e6e799dde11d3ddd5d0fbe2096',
        'lt': 'c88a788d3537c5293ab39a111f248309fbf59f0b65ea3d7e646b205337197822',
        'lv': '8339dad09955728f532e691e9d8919c8657cd75ccb40231b84151ffe861d789b',
        'mt': '0d6d659bd00bbd80d6b0e08808a2c6f338ee1f88a43fceb00ad0204b07e95379',
        'nl': '6667765247086e4e29af70101496b53752234dd9e2b253f18a13441c9b5127c6',
        'pl': 'b14f3c283b1aebd49ef6bf1021c7eb909c47954491c1e062a67a0da4b0baaf67',
        'pt': '8b62fc77a9ce644e22c1ffe3a6a477e7d8c7d4e99495bbf90019fb8256d39d62',
        'ro': 'f29176c36994ae8867f56c6fd8e794c0d1e791e3c43032f8d38cbcf3f5bdd434',
        'sk': '5f9cf9a46565cfb12aa74cceef5bf75907fe3213add6da22251928a860339e8c',
        'sl': '8d4fcfd7b850b2cac74bb72414f547d6a43fbe50effbb03ae4bd92077b02b519',
        'sv': 'eed81c4d91f77394642daf41b6cbaf3b4d99ddc9de0b7283f4a7e83c3a8215f9',
    },
};
