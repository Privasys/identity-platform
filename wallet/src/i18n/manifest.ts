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
    version: '336b27e6a9b6da11',
    digests: {
        'bg': 'da1d41afe81514e87fe153091f59902ac80b6eca8c39c9779d644a3008634160',
        'cs': 'f4b5eb37702dbe8dfb117e1e386b754a7b0d3ad4fbef622fb819ed6ee367e1a8',
        'cy': '56dbe12aa93246297feb34a88e9b650cd394b944bf1cd1a79387f8e4497b3464',
        'da': '432ccb15b03d40bd33426890fd1c6cf28069862a62f4218de20c3228c7fb1df0',
        'de': '1f4eb48ead3ee799eee93213eaa75db664a411e69bc41652d81954d6a2add4fa',
        'el': 'a251faa5f386f43b2cfa7929e6c460404d49a32de5ec8ea621fc02f353aa2f45',
        'es': 'a57f0c6d9b13edaa252faccc10705162573d7c2b52073f74356a38a75ffc5269',
        'et': 'fefcc40ba63e9807a9672a47bb750b2ed67e88dbf14e11563fcc3584b4d97001',
        'fi': '709d19d33807c801e9c6a5faff3847cb0eeac3dff124cf076555c25904aa273e',
        'fr': '7ad7042f4b39e2577119b55854a45addadc5e575b14a7ee3445559174d5fc323',
        'ga': '05e3f2405f54ed702000d243ef5c958c14b41502c8b8de78a079cafd4fe2f0ae',
        'hr': '77d75875d709a1fc7604e16ef326c5ee3e9dc2b74b73293327b8f8e397a18cc6',
        'hu': '153d3907911a089b4005d329ca7796ca406fea7e4282bcfface0893bc84fae79',
        'it': '039f3ccf8097d67b6f20d6b7f12cbfabadc7a1b45e7a541282447e6307d71b81',
        'lt': 'dcc08d946cd86fe5f69747f506d8e69c3bd57cf04c4064e45c050ae9f0eee31c',
        'lv': '32e8aa02d97c8a271b22e380a6c8ce7d07d6d1921e55d69c531ad2e593b95f76',
        'mt': 'df0badd35c37105092d5e21cfae3449126b78f2f5da4cad8822888105fb8a527',
        'nl': '1cf69f964b67a4801d84c897b3d524f7b4767222dca389d6c25b76da8c5712dc',
        'pl': '8f9af430257c087a60a3fed7498aad6863029b85ae7440f29c334645c8dc2ace',
        'pt': '056392d7d3aa51ac8d4a8581d035d22aecc0a2c9c8c32b1749605b80654f0c3f',
        'ro': 'a5c40d053a9b6a9acc3915e4902b4a12a6d83a21e8979b9328698209d814c228',
        'sk': '107b708059afeb793dcd8a3967a5c64f9ec310cbfe453873475d67f85d4f24ca',
        'sl': '699afaa7422c5b413f66ffbb9e5d9ecb7c408ac34ac7139b0d612631e711cfc7',
        'sv': '26be62881490b71cb838bd958fb94eff76d5a06c33b67a51254a866edc3d8d86',
    },
};
