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
    version: '3ee17aca1fe6d31e',
    digests: {
        'bg': 'ef2974ff49b2816b3729389dc8929f19c2bbff2755963fc98b905bd27ba1b36c',
        'cs': '8399d2604f77b8f536b0d7eb69aec6d80f22136d9e2fa48b611121183c78415e',
        'cy': 'a941aedb05154ef7b119a40d4e3e38208d7f85306469095dfa675964b2a1a361',
        'da': '666f1f3f3dbc9ff42d5c09836b868d6f6e2506f0c0805bd3f90c38311cb34979',
        'de': 'bca17e21d6d4652ea84ff54a50f1116104372c8aedfd3724658cd2faa2fabbd6',
        'el': 'a5ee10c4082cbad36a40a85823df8663f07510a06159f7a7559f95a1afe4854d',
        'es': 'e85424cae0e8bad1b7ea95c6c01e51cf3211f93bb056be73356f27c5bbd3ca5e',
        'et': 'e64717d384e30544519da228ac746e9eb1bbd1f41f7a7025d1d1c2f3b860b9a0',
        'fi': 'a7debde67cb08277b7f6c0239213fac692f2896578a5834821ddc811c7f96597',
        'fr': 'c201144c7689a27636bb5f69aa3f1d05fa30c21d8ef718bb50367940f6e71fca',
        'ga': 'ccd682bfd7a730e81bdd7fd4ffbe9623c3c6b4354489fa0b86e560e82866d833',
        'hr': 'c206d9ba2dfd3bfa5b58b956b6350d40f0421e8202d100579b14e15dc7effa1d',
        'hu': 'd7bb56eafaddfc8d32d191b804fcac1e92bd0f0d5af700aa3eb69bb24cbd32ef',
        'it': '252be5007a65bdc55f6cd1fd874b13ac7b110efe85a799a97e272e3f12c27f53',
        'lt': '40ef9ea4f8ee228e0834664bfbb026fbe6a9b3272fb67a6300987a88b055aaab',
        'lv': '474e9fc3703d3c2a53869c464a2d48c1eb2eeb595d5d30c92f810ad5c2f9fec5',
        'mt': '7f7a3fa012649a71e93202cb12c725ea5ffc509fed7595360dcc37bf272b4e77',
        'nl': '8e9671543aeea445d58f8fb3135a07cf202289f345f705b9218da3e6ef360d26',
        'pl': 'fd4a92ae5601e490445fcc40bcb11ed4e460b6094d50fa84ab12336d1e7e1bd1',
        'pt': 'f3af4822c8081988aec5ac022db7cd1aa1deb58d2f1c98c65107c89a2b7e8a11',
        'ro': 'afe3ee26fca686ee2c876c84a37b508225a1ac105b4092fcc590a0c413309c5d',
        'sk': 'ed9c44e1a07b974c5d8cd7d0c403a222a1396008e8b7e01c52b276aeb9b23cdb',
        'sl': 'd5fce91b9bfcac980faad9d6956bd3900d190dec1477c340a126cdb9a72e717c',
        'sv': '5cdd424ac032e56e6872deff4f9b126269bffac26c4644c5983e44dd133df80c',
    },
};
