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
    version: '3e7768769b57fa88',
    digests: {
        'bg': '92c2b43ca1eadfa40d3bf41097bd4151464cf8872c1473a73606a7efdebb62c3',
        'cs': 'f9942f6d11795da723258b89ac6aa4f54c969eb10f2c41b8f3c88523361077ed',
        'cy': 'a55cf7a7ae438401ecc2168081b7c83a0bd8571bf3913d25f92c68d321266599',
        'da': '16c385fcd1afcb2e5b4454d1bf282359af153905a143a19a0f33493c65632786',
        'de': '3a54a21bc0c43c7f63223cde3308ae98a548ab133446bb9d094203f6eacbe9a9',
        'el': '2dad3667375821c1ab05a0723c17360d1d2b872c4c31a9a9ad83b850742b3b00',
        'es': '431ec0b9e95a860fd38390494dbb2280e3b71d0cfb4427f0161dc80c608e132a',
        'et': 'e24eec91c60e793e6adb55905322c794b92aa67aebf11bc39aed592b44d7cdb4',
        'fi': 'd6ce726a1e6d9e2d8451d3286bb2a9176d55e2378aae8d2a3be4bc1d9afbd290',
        'fr': '2bda833bf36241b7f751b0f9a8f957a052b8b9dcad57e955a62fab1d705d9e5a',
        'ga': '291c46cbdfb27beb4b150ac646231cf4c11bb3bb55ecee9abfebe7c3a49ff323',
        'hr': 'c292d28286a5a290930798430da3f82132810dbae88dacaa6609bbf9728f913c',
        'hu': '8e42105dc233aba683eccf7d9490eb06d55b72ff931d7815acf0b568c88bf5b2',
        'it': '5ec2f622538ae8cc5eb99c7a08d3ee788611b309e58f995deb262aa518819c6f',
        'lt': '4db4244fd8ed481edec2f18a9ffa2d46bc85825b3fbee652e3b155be6094cd95',
        'lv': '4f0fd38dac2f31f47a3bd8a307fd29b9245d4037027cdc203f4e9ab97bf45416',
        'mt': '6a0514ee54cafb6ed86961e2fe4cadb5f9ef1a5c8cfbc773a879c8b0e113fbf8',
        'nl': 'ea0c4a76b8599420db8d1bfb452a02653a670ad952c198204fc4d0c854f837d1',
        'pl': '2414460f85a393598b3a4cb998958ba4d17576de00072b1943182c903df759ac',
        'pt': '95dd9157e9d0fa0f9947cc984ed74483b651885c7fa85ec7436c93c8ade5f41b',
        'ro': '7445a0627003c95c513ff673b8083ad12c038de49e51a51651c473f89a601cae',
        'sk': '4ce7f4cf8c9ec1f35c582d93a198c893a79d9fc92a10335c6ace0673dc1e2647',
        'sl': '4a9f40576053812c8081b3ac5d9e52089ef8841c80dfc39105555fb1cb4fa779',
        'sv': 'c29a1ae7b1fa629d46c48ef0d9cd53ab76f0a422364d1b276af2166f8959d650',
    },
};
