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
    version: '41bdd738767269a8',
    digests: {
        'bg': '50ca9557de2c075f6a7c226a7aa32519c467251b6b61486e03164a8ad0a3e61b',
        'cs': '371774baf5638384243c2aa53b63152636a368c795e2676d29eb99b529447a3c',
        'cy': '8010f88adb51cc9e780308a9d76e02afd5a64fe6aa62504a1a317757eb0f4654',
        'da': '19b901db939749643d0fe291217ae104e7777d2cc6820fd3745e27e61ee4e04c',
        'de': '446be0ea465ef6f93c5a78bf90f4f23850bf2131d339bc807cc5b41b19c84120',
        'el': '58aeb447b146a4c275dd8b9b972b1c7a5a2e22e790b81f87fd30034109d4cf57',
        'es': 'd82bb831df334ca467d3b6a0fea1082eedd3eed7f657fa5d37bcfda41d6cbc56',
        'et': '9a0c2df11d9c24bca3df0a7e2e39f558005df631966b94de41706dcb03a12c0e',
        'fi': '97c3747b7c4e5d90810b36c7b1916d11c439ad8583d63187bbbf1cabbc4983a7',
        'fr': '9b4b6a1b0d1be288c824968297a8d1907ccb9caa3ed324d2ce84edfefe1cb61d',
        'ga': '22822ac066424f69e5179bded4e9af4bee22d79fd7a489f5d1deab70642e9ab4',
        'hr': 'ba8ab5a9d91a271c43b2ec535da6553b31f944ef205bc73c415305781319a810',
        'hu': 'a9c7603acbb2df8aca258b9b56b0269abc2e590f8b910a78ff7e60c7141121dc',
        'it': '75ab1ddb9593476361e73f2cc03390216c176921cc67b373cb0b7b69be5df62c',
        'lt': 'bbfb3e698652cdf83c58c176cc34581cc38f6911abf27e7fbeca43ff385e6b61',
        'lv': 'f73456dc076cca09dea497b425919185d552c81b3ea8f2e1469843a40ec79057',
        'mt': 'ca36ba84d28da8f1bf201fefe0e050d7e7b1be696f985e29ce0156305d6b7257',
        'nl': 'd65a55b12b9686190e82623c3aa5d4d50f4f7ed71beeb946f0f1f570a480283e',
        'pl': 'fe49ff4b5a086e36991eb6bc534f1563de263e301e40899075d475985e83a4a7',
        'pt': '6d78451b3d1aa51b181d3e2bcc8869dabd60ec1a36e761b984777d04ac5a43ca',
        'ro': '3f917c8df7e1b022048e3135a4e63784852614306b2005c822e7114a08301321',
        'sk': 'a639cd8b6e05d355ae692c871e67fa5ddcaab5269d05c58f8304cffbb43cdb11',
        'sl': '0c7d1cb28dd603fa3d16bcbf796a9b57b2fd7f455a9968549accd59c0e38f8b2',
        'sv': 'a1dbb04d156223fb783209f0ee4e2b5e23b5903970279db77a96f3eade3d2010',
    },
};
