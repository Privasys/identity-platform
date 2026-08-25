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
    version: 'c5ca4b9e78f015a4',
    digests: {
        'bg': '050cabad40c73de4f3ebf2d7ec196e8ab055cae3b60ea1e40f7eeaa82ca67e8d',
        'cs': '1e452950a8700bf62b38c8d4b5b77cc5165adcb0af04033ec4e88e6c5a6cff93',
        'cy': 'c2520567283e44eed0576753949dc7d237fb8c549b59f1035b8c049f9c901ea2',
        'da': '5377ecddc8bd0f6fec934d00763b35dc5906f4b77cd22b4d0c4d3ab07bef3326',
        'de': '406cd978f6c651431377968f77b813782c4ab614a44146df0ef700864a197408',
        'el': '88413f8c9365d957347d72d3492add6ddbf0207d15ab34d40edcd8285ec5bbba',
        'es': '9f9a637b98bc62934f3fd1cbfa9be965002a58fb70c16ba509c7a79d90e75905',
        'et': 'c0cd920fb9b8a59637258838f763824e665e2c1fa3142732bbdb884585a975b8',
        'fi': '56821098d101c78064981275cd1d50b9a61ddc262ce05560bb364cc9f61e6e72',
        'fr': 'e3d03983dea4878b65228737f2a27f733546c553cf61a50f9d32c5db2cb80eaa',
        'ga': '1c9161e711366266ffb56dc067813f39da66de09184f83d7e5ee5dddf055e2f6',
        'hr': '10d885df9931d7d40086234872345959e66155ee4a00032f80d3650163048a6f',
        'hu': 'e2b7b45af90d1489d8da8f7b6f380913b7ac071e0dce1ee81fede639b31f5d44',
        'it': 'b2da16e634d97941fd8e330d507e9f9989e8e929b6d5df8c1ebda3a45a8a64d0',
        'lt': 'f4f77d6e15d269d6ff52966ec2c88dfec174fcf17bb0b391dadea7f8891bd14e',
        'lv': '9ee0ccad276593cb194173c039e5866fb76a7056e124037b302cca71d48dab15',
        'mt': '6e0253aad3179b74f832269983a33921fb7a0635ed030459f91bc63248633094',
        'nl': '1748bb622985875cc67d8f808052dbb5f4016ad6500587f7cd52f931b1410e2b',
        'pl': 'ed8653b7b363b40dff85489d60d0a7317143f7fe8af1bce5edde69e9519f5ed6',
        'pt': 'fd318054f7846fd397b2cfa946b0547db4afd4d6751253477039c25e587428fd',
        'ro': '5ce622364bfe53a5dfae60a89c0e84d63e79f5871a2ea98fd110fc700a7739de',
        'sk': 'b063d46cccf6fe61169b357c089a111877bf43ad31ee865866299930b3fe3a23',
        'sl': 'd656bd27b5b6aed80936ebc067dd93074031d043ec4794c7a8173562bd20cb1c',
        'sv': '03a43e408c11e0c90b58ee573815bbf7326aae2236224202af10f944089fc188',
    },
};
