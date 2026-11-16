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
    version: '851d25ffc7590fe9',
    digests: {
        'bg': '3825401350bc9957ef99f6db3e86c66462d936b9b63423e9ede38b35fb1f6a65',
        'cs': '229829b793afc8936e79e2f4746ba0287629accc070c2c0f099cc6e13440bd0b',
        'cy': '222df9d827311a3ba41bec124dd2c8ff529fcd0972e80d4f93aac512a29ed768',
        'da': 'c3bf2bb55723d3896886920bfa71da0ffb84fe9f64bc3f116efb7dcd8780a8de',
        'de': 'd2ee9a754786db5cbfa77b354d9c4eb65216b5d61acdbe40146bc9f2f2862143',
        'el': '7621ce3113857e69f8ed62b99ebe5e2ac47836c49682ec1a9e0cd2cec9c09ec2',
        'es': '3036d6f41392eb007ba9af86b7c3ccc0d028c815e35a002b3b319b06a6cc35a2',
        'et': '8c1dd4a6c2224788c37dfca530c2ab7084eee860b87679dbc75622ab9c5e3750',
        'fi': '4456f9e0787cb74b22e06317710357fc33066d5a9923e001a52ac386510be338',
        'fr': '09c81f13ddddbce1140fbe652af6d1d0879108fc754682f9ef85aaabda6d1cae',
        'ga': '9386e716ddcb7e73903593b61dcdba858ef614801befc68c2d7b024e2d4fcc33',
        'hr': '29499abb7eaa55a54d172a034b25aaee3632a06dc74a7e204efcb9644ff23094',
        'hu': '7a20ee146884fa2f6df8ce32005cfa70b81c755055d907d7b46586128ae3e41f',
        'it': '07fe08673d324d98c241ce72241fc31436bea081d520066be7c7affd3f4565fd',
        'lt': '6f156b30136f5b525d841f9c7c3ae735e4fec5ebd770dbe728fd45926816d390',
        'lv': 'a93ce918007e05dd2d0485b8ce9e8442c90b3ba2fed561e49487d8f193d3c096',
        'mt': '332161d096352670910a71f8c440a1230a01d38836b84c0ce11c3eca1df9b45f',
        'nl': 'aea15ea4bb29a4e2529781224bf8b63136c1556cfe3987c888497b5bef4589fa',
        'pl': '7d2a342a998f49799b31ff98763cdcf7d16fbfe3ef6511f7ed8bd8d2e1507b2c',
        'pt': '1cc4c9b4c3e9b61ac55a60410959b632aa810bc1e46f966b2fc478eb3c45d334',
        'ro': '91f71073fa5525af0e7bbb4ab87b5255fc65605714989c01ac41b498305d6f24',
        'sk': 'fed443dd4d023a90ce108c618784da4d5fb10c72db18e989cb95d9324b28956b',
        'sl': '540c14296b61a145897e99ba768385f6930ebdb3dd92d1aba3ea2824bcba7cc5',
        'sv': '0b674835cae594986ca6d4ca92f30df48f032ee5faa4d9c2c94a09a34763ebf3',
    },
};
