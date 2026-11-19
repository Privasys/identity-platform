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
    version: 'fc8bb2c7f5a535bf',
    digests: {
        'bg': '567dcd4549da38329fea3da39cbf055b4fe2d6abf04dcd6f58fd0261fbd7b34c',
        'cs': 'd700caecf1ed30731f36052f5e490cbdc2e60db8a387b7088f9cbf3ccd80428a',
        'cy': '6048d9b63b485eebbeab5d36c95377a1e36da7a85bf9fe5d068e6ef8c56aab23',
        'da': '9768f1cfa3c139defc9ce1272618c0441f1905122440fedac504bbda31ee2f6e',
        'de': 'ae1748712ba105f0c3a2408953741356d333aa7420812df307f6daae81d22424',
        'el': 'ed7bafdccea9fb348355ce02366c1c83d01f8e2522ef2462fd463c5026d9e75f',
        'es': 'f92acf630a81ceaa0d8d53147d8e2ce006a3c098365862f5eab4d5f24e47a244',
        'et': 'd2e3cf95fed00f2d5863632b23f468f7db45295fe0b86992652822cfb69580d4',
        'fi': 'f89d6939fa311219f6cc36face4665cc9590178b33ec959dd492d90cdfad1f2a',
        'fr': '993014be8a183eeb1afe1c5cfde1d44e998ec1662d481ca46cff1e7bc7897683',
        'ga': 'b43363c45ad54a166c55632b16551c9be4956b62b5d103240c6ec88a6212855c',
        'hr': 'e92292384dc712509f32a84e01a33baa04dd93ffeb326f45001002960b164558',
        'hu': 'f78ffe47d1670eed1c6dac9041501e000cc4098189f5e0cbf9ad8089ed6fa186',
        'it': '58929668755294ecf03e460e9cadfdc3a1baaf3731e2a69d62dc5c9b0516075c',
        'lt': 'beb1c7fce3d42c6cefd3ff64bb56dbe4bc90c24874b6b982db179beb0c49219d',
        'lv': '1552d17a8c916b6e00a60f0bfc08d7429b5c27542190bc467f19add21965d41b',
        'mt': '2b60bc6793ab316d626d91e5b1fd3f5363a8f47329c42820acfe0bc25564647d',
        'nl': 'bbaf21a38bd12e71ce30386190c22aaf99c080e5f8a48d2ba74d7cf4f815570c',
        'pl': '7429136660ae3029d55a86f954e6e2b1fbf6f953da3cf4b154d85a242a72a479',
        'pt': '3b56a37bbf694cf8d262bea380f13c41aa2a59a5f472390252808fe860c7d9b1',
        'ro': 'e09caf2fecfb1a0401e538ca1e2421c8195a71a70330c2afb9329333b356e06c',
        'sk': '4e38dc5328f3502d7b446168e0c00fdbbe36352e10a288f7eb7e9f909adbbef8',
        'sl': 'dad0c0761495d45daee1e09fc2d6bce1c4deeaaf71dad9869cccd765b47caef6',
        'sv': '64fab1b03de8eb3c1c50e2584f8d4ca36b142181576ce9d3627b0593e7963243',
    },
};
