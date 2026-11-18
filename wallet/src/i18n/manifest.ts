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
    version: '9404ac3d5b78b91d',
    digests: {
        'bg': 'c4e4b27e52e48451ff2869a9b74a06e310d3fdc8f7d50052216d85ff7b1c13e0',
        'cs': '17b90ac764b12995240cf5e76f2cb2483a35c68a16d076e282a072fd456e1915',
        'cy': '9ce2b71d30f5cb344c6d5ab2a4439af02e7ef87cce31835522c8f5d301637880',
        'da': '31f977800a2d791a73f5fbb2da551405d5fa4cd9dd9d7295d5741d402e9486d1',
        'de': 'c6123f27748c848703a7c0adbac2c595efe4f87e621f88e637281804c124412d',
        'el': '944861708ca54af46796511d6c37c2235c47bd7bbf97d57d71e91f1b9f3d370d',
        'es': 'f8606cbeed680405288084d49608c7269e2c7b5cc964df2b78bb13ee3ce541e5',
        'et': '3ddc6be1061edc5f31127a891a0254cc687c7ebcf357956c2f59da3b86894e73',
        'fi': '2a6bc6b3eb5b09b953a68a0af5d9effcafb973d11e5655f350486b0376745db1',
        'fr': '74fff5d6a26e4a3441b5edb7b61e3b15f8361252e569605d46d597ea93f3004b',
        'ga': 'e73bcef22ba69f06cb7b7f71c7b16a533150d0811b2f6a8e10e057979a7fd33f',
        'hr': '5ae1c05f45cd4402ae8fb49d67f8403347291e7bd6257441d89df3d7784ac57e',
        'hu': '0e131e16ebda2d9679cf96b05b854b5b7f5c3d3f0916887a668c52e4c0829e80',
        'it': 'ba3b451d3cc8975eef0e5b68117af6e8945f5211e5fe8da3977df9b758bdfc20',
        'lt': 'e76b4f7e29f2244e0ae334bf6b754ecbfaa00d48bc6db673f046dc71e8dedad5',
        'lv': 'ffbd6c5b64320ee16ad5ae019c1b3c74eeeabc97b7bfff072ba0d48b4142ab66',
        'mt': 'f30e540545e67fe51229869124c03a0e9e7a9c1d484c0dc81f0548b8b7bd7e8f',
        'nl': '71b27fdd3f452a5d5a6aa70231167946015c950e3927beddf9f8bae42bce92f5',
        'pl': 'd05d7ff0e23f38fa80c448c1f1d5f1bb2d129b014ca783c258918cc1ff6952f6',
        'pt': '980a6e40c3607814ab72f4d9a8ee4043f24937bdea1718e49b6d6f1cb2aa2834',
        'ro': 'c3c787127638608be1913532c48f7629bdef4d77e1db2a9ec0e7b9c4e6ed9718',
        'sk': '40a05395e7cf00d7e34843527795422f052a76768cf0645470c9c541ac766b8a',
        'sl': 'fa47b623e7bdabdd0de7972f38a4a370eab94390f774759e86a26223c21be7b9',
        'sv': '820a082fa7c737c19d368acce08d4050114043ce6bea42839d2d7c1d88ab48dd',
    },
};
