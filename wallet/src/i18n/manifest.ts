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
    version: 'bdb07a54caf089b2',
    digests: {
        'bg': 'fa9ba8cbda850834a3474fe975eba45fa6740b7234062d1c6a9931395d3dd1b9',
        'cs': '0e66cce728de5c03fd9e44eb68dc78f039a5793c9df815e1122725c77fcf0148',
        'cy': '205f225956c29f48c1ebc8111df905ecbd949fab6830a88b74d91677b1a5cc8a',
        'da': '2d2521b8c9729f79d7feea87b41fa90838a2a51365063a3e739d579388998970',
        'de': '731762e802e60174e5ee147256012e125fb739983b0c9287a5c7ce6e770d966d',
        'el': '65750e36c29f406427b519d3f7c0bd162c2e6e403be52ebad6d7654ea77de4eb',
        'es': 'b6014af68261ca3558d6e80460be4eaa60999902a61d447f032184bdc3df8d91',
        'et': '3432b71815a77e3cd4a490712b2fff9ece394ec153b01f8b2d65ef76c2076aa2',
        'fi': '1b7f247dc9f53c8280a094f92fcf711b803d54d7188b73caecb6d6def3231525',
        'fr': 'b9f222197099388850ff9d316b9a2dbdec84bca407b079f3082d6663083c871c',
        'ga': '7bbdc8aac5b77eedba48d8ab92d4947d9b6001cbd73e95ec468a448da95826e4',
        'hr': '377c00c9c87c4a2bd6116a8a18b863af18304ee548195df2211256990bcc963f',
        'hu': '421dba855e412677f5b5f6e4b2a75d16f76afb938e831ca5c6f5b63a430207a6',
        'it': '6532e3a13bc3de8550e312c51369f1eb3f4a007e1c3d41cf303c5828d6df9140',
        'lt': 'fac9f24a8e2355b0a6caa31c17930f76c76469cbc1503b390b874b4ba2640857',
        'lv': '7b4a838e40a9f41c727a98073b513d4b103037a584cede0ba9e10c7e148838c8',
        'mt': 'fcff8064e5a29ab499fd4351c0f676e70bb83b9f7dea77467ce9087fda0463e5',
        'nl': 'bab1adf03a9bb8b6b05d887413b912b02b53a6c46021f907dcfbc3766f75b390',
        'pl': '5272374c97d9e01b71a8aa584b13880ba4ca50eec6ea759b3b0060fa77487aac',
        'pt': 'dca9784b6b2bae99420fbaf320c3e3a2fbef6867ca2de2cf4c6ba63f8ad71d34',
        'ro': '4fd8f0b96cf0b0f7ba3d3df7cc2688c2c18e33c536cda178cfb1be4a0bb1bebf',
        'sk': '90f3e5cb6422a85bda35a89193990d4775bfd821de2e723b05126dfc3beab44b',
        'sl': '1f9c8d29d90709361ac11fbac152081f5fa512b7fe0ecd7b4d93a40e47918a34',
        'sv': 'f7e04a88ec540b9e2db4d4bd866d32d403fefbb650d1dc72242bcbdd29cf4959',
    },
};
