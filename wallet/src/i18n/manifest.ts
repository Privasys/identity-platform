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
    version: '12838d4e4ed3ca4f',
    digests: {
        'bg': 'e23b9aa6274814e9f0bb070165e8d30476f105d6efe0f983bcf10635fb9078f6',
        'cs': '2f150149d54ddf96146b08390cc6ec27aca70fa4a4c85f3f89679ef2fceadf18',
        'cy': 'efe55cbbdd721931db6fe44d25cf9c5aae284de1b0eb83016e9dd54c1015280d',
        'da': '988a226ad3682d50a7b2fbe26521d31086df9d868b2a97a1ec8d67018b16571e',
        'de': '935a1ec694d64481d5b37bf132fb1eb6f2dcd3a24956715a1811195d03f233b6',
        'el': 'f76edd4ee50cd37450cd77a1fd459118b6f9ede0da88b18a7413091e55bf4d8d',
        'es': '435e5ac742152874711966e5ac188353e08f1191bcbcf67d350bbff441322561',
        'et': 'a6f9d79bc7193d6d26476a7d19242fb8e019def36bbfd5467a4fc9ac1f5e7455',
        'fi': '2caa9f4a5838de114e5558d2d2880998e1bf9f30e12d1244e1d6bc601fa0f4f4',
        'fr': '9c51c7c56aa10a4cd0a1124039888804a5938dfb65b2b847377c13e1c633a560',
        'ga': '19a4138a9424f619dacda07c91ea52be7e9a6a5e83bcf17f0320bfcb9e5e1867',
        'hr': 'ad0244187bfdf122601b6671a4a9e5c7108ba7c22305f29051dd72533a08f742',
        'hu': 'efd4ed7ec6b909100da8b1e8a56047cb879d3fde0aff95b5c245c611ccb74c12',
        'it': '618f448c80b3998f940f449efdca7f368ed90dca76a285273530b88dd4e465ae',
        'lt': '4d12b1ef77393937e4e5dfb5990b5fd2f9f093421158eab93c801a0dc40cba19',
        'lv': '7683a7cee9eebf1e0d74f497a8cc3d0ef8f445a778a1e2769e6ab03e7685d9fe',
        'mt': 'f23957f6a01aa7f0dbc4e58c5b46a63955e66f4fbde5e0bc260bc5553aceb56f',
        'nl': '006f25bcff16cdc940daaafab721f4d87cdef4379d639819ad229606907198fa',
        'pl': '29488dcc39dee04a58ca2b9a393fedd0e4757156111545d7acc9df3c5300c353',
        'pt': '764f10687410738fdae69da90a3088a3b8fe6e376f8d2bd93b7535c23c927b90',
        'ro': '50174203ce10fe0bff15e0620616bbcf954996b58eaa123d18d62e8b5feebf1c',
        'sk': 'cb6c87073db814e1328bc23eaaeaec9891acef17e509bb3eaa605880a5a02710',
        'sl': '9b93846a19140526986d97a8e8f723d3c61def30c91ca4728f3822fa8e7f6d83',
        'sv': '3a844edadad8321a8f05f8e5b8a9593ac624abd222168ff3fc111908be162da0',
    },
};
