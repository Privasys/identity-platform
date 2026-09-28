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
    version: '0528e78a5f187e6a',
    digests: {
        'bg': '5eb7273e90e385095891a2e780c2363740c888e8a6bd861a1ff78e8f9d7fb6ad',
        'cs': '95de17f999d0b0b35286223f40846cb62d26d143d436502760f94ace00d68d91',
        'cy': 'f8c00e53fc4bf11aafef153e515ad3686089a83805108d5af0e3e413b22c245e',
        'da': 'c36913700fbe9510ad0301397cd1937bc662e80eb327a5acfc629b42a6866b93',
        'de': '5c8563c835eb08785c704049d37d33a8a2e01a2d3038e9558ac0cfc4497b13a3',
        'el': 'ccd6ca477de97c52271b7feade2c855305ef98a78abbacc3a35e706efbbc0c25',
        'es': '0d4f9c8e26189f3b7f930400dbd6894ffff9833b8d1a34dda900a36f95de58c5',
        'et': 'efc8280d41ddd68c391513a7311212676325b9d7ae06f61329d6d509dd5354a5',
        'fi': 'f9a6ce953eedd5f5645c166c5c6930a9c5171d3993837efa093d4d915d3cab46',
        'fr': '6bed13098630e2fc1c108a3da5515f6d931c807b567db251bc5fb9a9fa12be11',
        'ga': '18907dad3dc8b4e73435b24927df87a8ecf764d2080f1290564caae1a892fb9c',
        'hr': 'c92e0986993335ed0b7de0a2f897cf4cca4832e66aabce8fd1f2e566a2820041',
        'hu': '85f0c15d860e0f0172fc2b0ffaa7762b9a6990b0941ed3c6218224a6d3fed568',
        'it': '7e579d4819c11830c958b695917e561c87993fa687368acdcae4267ee95ba3ac',
        'lt': 'c58035250fd448a204201bda0bcca6220175dbbc77d538a7c8312475a23749d3',
        'lv': '81e15843824d4152656574e0f0a8340d8d90d1fa48c53f010b52839b7eb0702a',
        'mt': '93e226f999aa5da71593033c14b37ca0de335bcfd8818d0fbca6097acf489314',
        'nl': 'bdd0e5de0b17a63361781d79890d6fab0995725e344df7cf4ad0e149fae4faa4',
        'pl': 'f3eb078d80d924890dd3dba9948364996199965244bfb8ec8e236b4c86797f30',
        'pt': '78756e2aab72c47ae8b96609bdb33d8f7eb0dff283a3a1376a201725832f2442',
        'ro': '71c9001bc030884ac96d9c8935cbb15df435a15781c6aeea35ccb410b227004e',
        'sk': 'cc5f17af5089e5eb608a4de91df04e23982c1869c9df6cab5243539bd2744dfd',
        'sl': '6fd4fc1f1089c4da381eb5919fd3669512d7d49a1d92674c913fbd055053eb3e',
        'sv': '97832a1f3bfc33cbcd3f43d3aca8e3d1e7035a3e8621d4ad40504821429e9642',
    },
};
