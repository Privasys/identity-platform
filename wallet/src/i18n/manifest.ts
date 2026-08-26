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
    version: 'c4232d71d3413587',
    digests: {
        'bg': 'fde8a374128d35d74b1ffbf8e4c86808c741de433619166e180974fc6cf23365',
        'cs': '6c3fe835a3916a903b51aae6907b50c9bb21e2234fada3f2a3f16968b4ee4450',
        'cy': '1b66db687c4cd57d2bc8034f3db8ae98d4b5322ed0bdb6a038d54c65ebe208dc',
        'da': 'b23231cc254994aef3949422067abb62f83afa41001f90a4c7b7caa301ee162c',
        'de': 'd456face2c49e0c03d9f9e1d3bc56841bc3238a05b09169a1156bda782bb9978',
        'el': '6cd72109026f3a74fcc2925198fa9896efa3255a6c45503bcf1f54c68b7f7387',
        'es': '3e16632b4417007cf91a482709fbb4aeeac92099ebe24ac46ed837a863a1d45d',
        'et': 'a7884984f54f1434f890cd30c6a85a6d0d0e72f62165ee2ebe76506a72911473',
        'fi': '901f94b91137500a0d13d50fafd180c3cab5ca077e3ea6935427db28f9d51c5a',
        'fr': '97c0b4c27ac170dfcb06161c72f9e7510372c0a9adbc3a47473fdcc9f965355f',
        'ga': '250200e16e06b2a7d11e3492a4e0e051db42e5c926daf07df027eaf7f66b8f81',
        'hr': '9b0480a9cd5ac98ed9c1a6cb2bde6f1b8ca1b809a429bb10e34d5a7cbaadd4d0',
        'hu': '36fc2c2c9ed03998f63a1681f67420c29cbe24eb8305c9716a6ed15cb3f4cf8c',
        'it': '158a5bf2de970cedceb8ef87479aedf5256adead971804bde79f2f97f8798214',
        'lt': '3677a5bd9fd657dddb26ce3708c933d8b7732bf4a2c0e2adb0c37e5d907ff160',
        'lv': 'e07d152ef06434f5aac3e53548e54cb8a814db58434363def0035f950fa9daff',
        'mt': '3e69177ceedb384943104fb6e84d20db51113d31853b14e88a865e8b753566d9',
        'nl': 'c79934bbb50d8ba917feb462409a04e52435118ce3f1775702251a37f41b53eb',
        'pl': '8fcb64e44288697aeb49f63732db0ef4fc595d90917a07c5b8bb2380d3e4cb32',
        'pt': 'df60b03d3054f70bee866a037006bb8126cfe54201b67344e6e709b5e8e1ac46',
        'ro': '1d1f77000138431cc816e8c5bb0b21f12960c3ae89e8056bc6e639c3ef3a6dfa',
        'sk': '47a90b251f0a3da99fb5a6a674cc7f5fb11564b5c993fb1d789318605f9e2c21',
        'sl': '450cafc592897ea0ff89e3be41cff3ea4870799a790f0cf6ba171b7cd9a280e2',
        'sv': '5c2afd445e35de59c02bcffa92216c615c35dfd1f9eae95f2651437acdae5358',
    },
};
