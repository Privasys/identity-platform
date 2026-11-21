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
    version: 'f79f75f5f54fb708',
    digests: {
        'bg': '00e15b97de658250e722886c1e2f516db627d27f2cdee2529dd79d9f194e42d4',
        'cs': 'eff28568b51b6fa7c4d6155f3cf41ef64280fcb767df2d8bc077c736f1b2a83d',
        'cy': '27c6e1294124a9cb7311bc9a6e312bf23b6c4eb4f265f9da2da72c0e7dc0d478',
        'da': 'b11f6681ace716eac0cb588ee63417cc90828c98d5c1910211b7a69773cfc999',
        'de': '940b3ae0f66272411753a8bad1eda3d8e36c077d6a8c58af956a97fbf240f024',
        'el': '65c2ed8287e380ac8925195c1e5c2c1d98a1688e80559e41b5657cced28b44ef',
        'es': '38d8ddaf56430376cb62c6473ecbdaa95d46b36bfa3a1c57d5b45b9fbf7923ac',
        'et': 'b127a4aa4995c6c89e97393bb7f3b62aa9aa110c71513df1aedc08d500ebb477',
        'fi': 'ca1b5336fcabe547d56198386b5e18089c6ee16e396ed0e93f2f04671b00137b',
        'fr': '4cd756b159662c211f06e92662d54282f098b27bf27368ae4469d20d82eaf69d',
        'ga': '5e27219e78cea9a23257146b972e09b6939d98619c8859d3c0d4d2de8928d825',
        'hr': 'edc4fc697b96b61528cf24bd317560e7dd38a0a1d4b6038d2a119ef6bc7cb503',
        'hu': '4d4784d55e6643f869d192d17401b9b9ccc624ddb1b25057a9b8f4ad3a1c14a4',
        'it': '89d0b4a1a20a075392fce821edb74baada8c4a163077fcc981df69b3ea059d5d',
        'lt': '88004e6cfa2b7fc578341726a93bf74d8f3b23c362e77ef740fc953cb8687edc',
        'lv': '718158d7584f006acdaa6bade92d063a66e771ff07e2d6ba0bf3b927f0508488',
        'mt': 'b2dcb9cd26c15f81ad74328a7f284a8339a47d632ab0e5d9b861ee65ec99eae1',
        'nl': '767af9ff379adce7c2c15832569273368f61d6460d37d6972ade44e23b86eec5',
        'pl': 'b46084fc402e6484fde99af80366b328c28a15714a933b7fb513b9f7d70ef319',
        'pt': '28ee7a1ba63e24f7a5f1ab2f58d258bc3cf688d99b3a89f0543887b782d08f15',
        'ro': '8ba2ca660aef0bcab386e09be328af6fcfa39fb4608972f60e3444ae61fec0a5',
        'sk': '8ddc110736b601715dfe087b154d2b5451c221fbfcc0e758b87533a3bec9d6ef',
        'sl': '9553e2cbf6cf7a5d6b3d94ac97ba5b8bb4dcf3a97594e5a71c2d2b6ba81ddf26',
        'sv': '05e94ee88e745d9bef5491ba75398fca7750a4bb5e05eec5da0a5f1c973b2617',
    },
};
