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
    version: 'c7562877d7876cb4',
    digests: {
        'bg': '8cb056b2bb2c41a9f3a98cd435628b442ea8256ba2439fc0fc473a483c35300f',
        'cs': 'b4a7ecd2fc86284048825704b45f105eeb2e0b5468c0167079a6210e9179cea8',
        'cy': '2ff1704239568d56f14610dfdab970ade6aef8d78daa2d14bc0f458827a210fa',
        'da': 'a010078ad81afdff3596525c88e0b301e1369d5f1cf6dc643bd9a5b900366700',
        'de': '8959665e67b5b5ffed885597ace8e61b7c94ba29d12b6915435e39d30dda6ff6',
        'el': '333294d1985ccb0ab3f0e50585e8bcdb62e83578375a17a3264d8b770f0d707a',
        'es': 'fba8ebd9e6089cf693d38d23e55dbe054cda3fa356a86f91d737717d4b8e23bc',
        'et': '47673e272832776a9c7a50ce5fe7efc3844121409338170c2c1c42169a3ce3bd',
        'fi': '1426babd9d384600663db9bab7a60054e73f85dc7bc94f0a216ad1141b12d6b2',
        'fr': '4637d325278c2cea5ef8a69c6a53567513f48d11e0904c20c8d56b5ee885e23c',
        'ga': '404d27c62fc0211818278331af55854c870fb720077fbede27be9e80b835f14e',
        'hr': '6309c1d1352e255104e88bed87a1b89dbb1c40e7c079a6dc1c210b17df7afa4d',
        'hu': '44183bd5de3649b424c157f30b316f89e9f77ce72f7af93520fa3964ceb4e745',
        'it': '96487238b8a5fb683b2da5fedc23866be0521ed97353bdf996ed632f03d491ba',
        'lt': 'c21e772ee640b39d50b8791e9f23f9cb9cd820bc5574acfbed3f3e3fc13eddbe',
        'lv': '3a9aaba78b05addaeb04ada67fc13839eaad61dea3826cc52db993150c8fb98d',
        'mt': 'd96b0f02ad838a26d3968b1901e2f0c52fb2326d57174a6529d1393bea575fc4',
        'nl': '6db388a1af5e604fdcdcb6833157758b8ea61249def43e02359a4e74d42c4b95',
        'pl': '02eb65b8efd49f354ec19ea2bb90b339e9d319e635d732722b5ff4be45e008f4',
        'pt': '911185f5a04226de9341d8831f010c0f026f548006dab055afece7b3ed01b070',
        'ro': 'fdd6528462642ab0a8bd92ba67ffccc1c91942a31b400550dc0386b979d0f260',
        'sk': '7dbeddece63457925badcc67ab52dd64188aaa550c2d690b3964a966d4f343d8',
        'sl': '471387c16cae2f82d757f3b8221c895a792bb48c57856870aad74af651f6f51e',
        'sv': 'd01173475f7bd4c2ea6d8af97f727834a314b50b83eb6e68f42e04183dbea0ff',
    },
};
