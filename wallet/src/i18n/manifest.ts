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
    version: 'f9164cfa02cb8a1a',
    digests: {
        'bg': 'e58dea69fe83ce11f50cc84df0d2641cbe0a697cbfce1cafff4d0245b37d9e7a',
        'cs': 'd9d890691eb1041848c9025a4c284a7cac56e0585e12d6ec22c0aac438a7eaa0',
        'cy': '7d33a4ca377f3de233b2ae63a36f700f8210e1bc01920bf6184298d7e3d8dfb2',
        'da': '5892918b7643f4c07b0578d95deb24154f839fd3fbaea386826522ee1ae23b5a',
        'de': 'f13d4f1a55575c70b13a6ed1ddc747f8fa22b4ed19d6c1c76fb7b4efae7b88bb',
        'el': '2a9615ca4475f94fc25fc77f630b6a5cc8dfb1e458d4132ea24ef09037fe6fe2',
        'es': 'b53d8e20a845a01bd6ee117aacbb55b72afe9983de8481cd6b1420a3aa14f1cb',
        'et': 'b69b8bd74e985f380f27d0cf8c39a57b4fac1c3088a6927cc57fedbc97f14209',
        'fi': '7be0bc1b6013d5c89ed663cb0014eeaa0c66f780465c137b4cc9c4f8033adb1e',
        'fr': 'a681c306380d4d7a471f07d5d27620ba1e5c415ed3ae4acd8742a58e9d5b9b1f',
        'ga': '487d16cd2c7d3a6bb7640b73f9c7fc2546b6c4f9b3ec6a4d6abd663abafe027c',
        'hr': '79c27a9d75c0969309c1f4cf3524ee01354d04826475f5cb6c5aa574790cdfeb',
        'hu': '6c405899fd0ed06d5979505e058ab89088cfdcb0633614823fe8bd91226a81b8',
        'it': '901138a02178440a66da37dc22f6f991ff094781b91e0f50d0bc9331168d6ea3',
        'lt': '38d53755870b791547a03773d0bbb56581d9d1dfeb7cda2876f6d7dcff9ae458',
        'lv': '2846fcab286e96ea52b4da2a4e1993d4ffe11fec099084abd28da005e41d5d4f',
        'mt': '10949f5d01cd793e0769ac43c9236806d4473b44324b20d688edc73c95f57b96',
        'nl': '17da9d6d6bc394bdd3457e694d3b604e5103a418c8a1a1bb22d5c285a5fa9f78',
        'pl': '85fff5d48fd5ed2f1370a04cd42cdea13291075e994833bf684beac9d843f2d6',
        'pt': '2c47d05b1c18e856f8c136a0a4e26d4761cdd4fc460280c25f99431da2e1f61b',
        'ro': 'd5063d83ca4214372d56941ac990411d7c8db8a7f4e22b1ec5e32ecc5f006c1c',
        'sk': 'a59fbeec10e525ad8bdb6f32b0fa0be4f182c7f027237a73e5940da5cb91e697',
        'sl': '0edb62fd2f4da2ce5d7f15bc788c26e8dcf2950d225a782e6d867106e00b974b',
        'sv': 'c08130e20359ae569257538974ad61033bd4aa403071ee92ce0deaf31d71a07a',
    },
};
