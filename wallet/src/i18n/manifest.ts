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
    version: '10da50da04f21799',
    digests: {
        'bg': '3b883d6169be769ca45ace43b65c0e704cfa9c67064354f336048494b0857f54',
        'cs': '3f0db9768b6e889d2e2e652dcc7e8ee5a2729de985f1e078fcb4c3232f65c537',
        'cy': '0deaea31891dc60c03e3343b910f1ba44a245008658b4314adade3ee7ae9d0fa',
        'da': '0a1f70829c58e917c72690a71c2c61bcff074ee8ca337e2b624063b6499f84d4',
        'de': 'eaf13d747db761a3a7246bc8744a3f5b142336c11ed21d8de449d96a882321c6',
        'el': 'f916e8cb26555152656a0c072b861db1544abf2f0e47dcfa5726f8d7a791fd38',
        'es': 'c5a79334f67e5743fbb0bdf5a02f52a6446ed4b4fecde208728dcfddb273d3b3',
        'et': 'c760b889de02a7b68f456a6435d71d3d93da40a8377ed1a43544c7d7fb56ad23',
        'fi': 'b2bccc4bc0b4811ae1937cb15e2354ae244a955c43bb1b96927f04286bfd9891',
        'fr': '1163497ebd9ad6c182726a37b6fde5f7486e904aa6f69e16a4312b7673bbcc7a',
        'ga': '0de284fca816d0bd2585ce658cd9768f5818bf48a7f788dd58fa530e4ee429ad',
        'hr': '8405ca6fd88d8bec3e5ead22bd49a63adebbc7f15bec2c4de34bc58e215d33d6',
        'hu': '99374ec8652eb70b4f4ed470b27b4aa0c3a2656fb4f351ef5baa42a4c1009978',
        'it': '26d0edfd9f8706df2d82fd5d55b4fe28192e71d2cac97464b600efd3995ab386',
        'lt': '7a1a502e1dbc90d98c4304a3baee6742cf443a51e624ba6ebc0b12894b31e12b',
        'lv': 'a0ed92a1078dd5489aaafa1c0c0bc8e773757f43a713852790b29255f049f968',
        'mt': 'e9a2f5bddd4114735e8e6ee9fa045f8c50b69c4c9545b63251c5185199204d4d',
        'nl': '3da5b98b59ebd6e9302f83018d3b95de18c6bfe23594c2d37094bd9499611c93',
        'pl': 'f63685c7e40bd82ca10793e6b8bf777b84303fa2b0eb51267e374c509b2a38ca',
        'pt': 'afc2f560e3ab3167cb9b6f1d9bc3d929cd30f2008427ae8af833fe36719fc398',
        'ro': 'a27ed22a52892c09590db42d26a59e27a2bad8d4c696a1c522a43db9732249de',
        'sk': '6b865cab0127cce66b6b54f811a85edd6074736bf884bbe5ca814d93d9ab2cd5',
        'sl': '897b1ef4d8b1a915ec4479f68e53a29e0fc46952fb6bc25330ba9e71b4187c66',
        'sv': 'adb6cdc7b8e06898255f0663d93d7b24d91b928f22d617a23e913716a8d33b69',
    },
};
