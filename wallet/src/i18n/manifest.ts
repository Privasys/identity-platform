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
    version: '45850b19e68353bb',
    digests: {
        'bg': 'ecce497da31608058e435ca324c20831be8d6b6a07e30fcd704b2a3d2040610d',
        'cs': '924cccc467584b71e59931f65bcd2e86f065f8b722f3ccb9531e7bea8b9c829c',
        'cy': 'de65e10c325924e8e568493ad863305a891bccb7b3d016359438496fe2fb9a45',
        'da': '5a02e104ed1da4c31ace7cd917738ea2423bb920cd4876fb4f8a3dfe755c7bb6',
        'de': '4bcab94fc262851d20ad691b42b04cd2fecf014f6a8b9115e9fc430af08b0f49',
        'el': 'cdc4684b134aa344899f349e2480eecee8f67c87d4da909732edf911a2a2acb7',
        'es': 'f8f083a8b011efe85e2893a7ec9e5217edc396c3eff5155e09e04ec7a8aae1a1',
        'et': '47f3a65fcd7f6b4a50fd8933bc5eec8a55ad908f5a42b88ec8b7afcafa72575f',
        'fi': 'ee9bf891c6109b21bc02e8ce3fce177357f7eb5809dda81034dc6e88323f8723',
        'fr': 'b255c019262cae27f0d7932e2f73605405e3a603b12fcfc747d0a0ad0c85e8b9',
        'ga': '3e4b1f9b38eb53a48c55438d1b1df43a92e6e50ed2732878f5734a9776ed7c3d',
        'hr': 'a3a70d224f82e7b326130c89310ad46d265f3ad3bcdd4dbb23c500e51524c2ad',
        'hu': 'cc42fca637fccde735c474a9f33496b34fe6ce4b3deffa45e2302cb02927c3fa',
        'it': '92f723a4651c6e1d20d39c99e9424e841ed71293ae38a0ac2ae713332108ec98',
        'lt': '3999b21ce0e115d73527f76fcf8777e8f840fd65e8aa1009c2893fd30977e39f',
        'lv': '62e4f2b855c23fad7cad32fe495cb98123ccaf351cb4d94542d95a50768ccf87',
        'mt': '1a8339c37abf6e394eb9378f00827be93248ab4121c138900d7a8df5632a1b8d',
        'nl': 'aba6e9ae575e8af8369ec0bbc757d05211c5363b393f0226a177502f2be45406',
        'pl': '440083243386b51ff9f3c4c7172c8272d836a4149e783f90aefbfb5fb5310369',
        'pt': '0121d24021ca61179ac41ec23cbc7228d7773f02ed245f897e428ef40fc347f3',
        'ro': 'c87c93a0164bedca0dba92d0b24398c4296a31fcbf2c1d3432cd8bae0d1e2731',
        'sk': 'ef91c28547887a5353234f27492f70e657676840e5464563c39a6a2c93ddb5aa',
        'sl': '216e045427408c6bd4d785789cd9d5bc7e00ac469645691e7149a602c8e204f8',
        'sv': '6123d2073e76082456ef1c2e309b4adee63740326beee7d35bf6ae12a9a8092d',
    },
};
