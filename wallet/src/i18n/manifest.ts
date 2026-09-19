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
    version: '3b803f7921d0f1fb',
    digests: {
        'bg': '46fad6b4494b3bf3bd20ecd6d9462cf7848f2a0f1af7eeee76765d8147cf9a87',
        'cs': '8e694a4507e2a5fe2ead4ca7e748dd655398f1ae3e82248522b179dcefee5412',
        'cy': 'bf0ca9010e5a457854fb137e6c28954ad7a94b138bc254d9c488eeea683dd987',
        'da': 'b33cf585d464f345a4af91882bb2453e1ab8a72008c2e0612730259cb7be5562',
        'de': 'a5c67b96c4b06674007300408e249184cc73a25b2eb02d8a77e16e0750db30b9',
        'el': '0778feb1b82ca3ad938eb82fb7890d80119e0c66b6117d38c5b5da127746396e',
        'es': 'f37ccb643efcec11ea6022a33dc7511990125799c68c5937fb02ee75da58583a',
        'et': '1c8fecc6e43c7b4f649e3566919e8765e1c793e7ab12fc937a0ac4690b6544b0',
        'fi': 'f1d456fac927a9b5a6f7f8d02dc6bec6a8bcdb3f18ce933dabf7879627f5fa13',
        'fr': 'dfab120effb451f90fca07c6aa679d1909a17fc71496e7525d61f9ee9ef61e31',
        'ga': '5bead0558af8b4dbfd65af274907208d091a2dedd5335fbe2e8ea0a5d2d088c9',
        'hr': '9bc32860fca7e5fabc45904b0da2556f51c70f0c0ae24008162f966f80ca049f',
        'hu': '74ea61ac79e26dce53cec5c595ababb9e0860daec262d460815ab4d8fff2d897',
        'it': '76fffd2c4125a91ead8e898388106137efe809484d7799c5b16280c8211a8e91',
        'lt': 'c2cefaf7e203cb82d2d8716b323f65e34c581d1e0bb0cb22556234c985dd3190',
        'lv': '76016180dc293319839fb4cd64bb6b863b1922858a99dbaad544845c1dbe3a56',
        'mt': '6021c73d81975fb55c992a356dba31c163713f3ef7e730f6c7702b997934b3c1',
        'nl': '1e398a94a9159fa1fe23f1a5b52a239541394d895e71b840e2d69afe53a5d457',
        'pl': '425e9b1bb81b83666cca222e406efc898218e6fefa080d96777740a4e9ca9cba',
        'pt': '71075cec9065a5b71ae9b8d19ff79c9167828e3bc0f89662756296858cb9711f',
        'ro': 'c3ac621df623ea7dc5a060d512008cf9f29c5059e5e00961b6b522cfe61d596a',
        'sk': '43fdcba7554044ff19261322da995fc3b6c8093bb45c3c4875c2e39ff5f887f6',
        'sl': 'd93d61abf2590ebdf7956bf61768b93db5bed51d5b769c99977bd2cd7be39efd',
        'sv': '52aaadc6894f046838818c7b4bcc308f620f5d71b12d5360e5313e9bc78db595',
    },
};
