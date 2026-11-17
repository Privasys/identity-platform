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
    version: '0580ab0415a6287a',
    digests: {
        'bg': 'e2e2b3e894929b6215c926069d8e440bf44f09c80e546e5d12ec582198ad39ad',
        'cs': '4321cff7ce09b30247851bd3197551143a1dc6063426002818d76047f43b8c09',
        'cy': '20ea8833d15eec01a69db1178eacaa069ac405fcbae8b17f0f66cb547dba63f1',
        'da': '76c73f38128d3ac0756c021c9563dc045aec25e643c90fbf70fee7a78d400a20',
        'de': 'e7ec11fc4d2443e18223938ed55e8dc22089b99bddecfb65f0902a207c87bfa3',
        'el': '3fdfd035474df73d0b96df981aef6bad61227e524a258b92ba32e35885216f4f',
        'es': 'edcf392f426c5cdd453ce52b04655067d23ff84823eb75d3f1d58c6e05c3d0fc',
        'et': '88ef6494e6de992dcd8a1a4b820a06e3cba6656bce734f1753ff45530e729a36',
        'fi': 'ccde2fab8e978a4a66cacd80125466039ace8d1db92baf844f8ff98c80845713',
        'fr': 'c5d6199a684d043816489327f1cb0566654b751c290d43c892c11f2bc906ec12',
        'ga': 'a2e93cce9a3e7d32420355153cf400eb5f628d076ab05637dcb78265d60ec3aa',
        'hr': '6102725a6948bde93d8400b1e33c298dab2a0eb032abe6e623466df0da31d21f',
        'hu': 'de62b7fc59473908b8b58c82dc07983193ad7d381230313f50e661027305f710',
        'it': '6279044096cf58c6b6011dc94fd4dcb6e228a5ec5694c84033f1291fa7cb9f61',
        'lt': '1a8c4c0391c78607acb6cafe377900574de154e25570c4d844db8d2b8e0a669f',
        'lv': '76edeb9dad7562802f6bb2fd9c57d9ce097dc6c92e74a909cd4778655dca1021',
        'mt': 'a77637366fc43dc3c4da2758ed4727f9204a87f1f61b6f529ffe4db5e1c106c6',
        'nl': '3dbf8a6de05e172ef8df14aa834b3101a0d95694e87d6a1e1701eac4ece79819',
        'pl': '7c51a0150b7c1cfd34e313f55bbb69083e1609cc5602619d87003b0be01a04d1',
        'pt': '38ae92663a93168d452045ca487cdf63f91027c0e47b89cdb76da0c805d33852',
        'ro': 'e5d58d0ba35be386f1379603949943391498cb29657b12be72dc469991becdae',
        'sk': '111c97448d3e928c28fa74883908d78846af406b059939469f1d6b69c397e841',
        'sl': 'cdba1d86ea1518a9a08c14e9bfed97505840b3be82e3d0a6c9f4606a140659e4',
        'sv': 'c475a2609272a582b3151d8e29a0e16d495c374a39c828411c957915e317572f',
    },
};
