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
    version: 'e8ec964fef759f8b',
    digests: {
        'bg': 'c8db8c0ac8dccbc122fd72e8c01052b21d4095a4d78108a9bb124027818cd2a0',
        'cs': '3360cf9b1402203bc8fd41857a023e83da30e11b5df0a577ab9160ae40dfa4e0',
        'cy': 'eb846e3b102b05b4173c66b1a80371757db90f136affa2d661b7533c97c9a873',
        'da': 'a253d4f28b1477cda8c997771a786c2a563e40b905d3cfe6718a9ccfcbb7d4fb',
        'de': 'f4cc819b57cad51f1d09fbdbb097acf561bbe4cc54078587265b70ce6d35ab8a',
        'el': '6903c9afbea19cc3aa3b74d38fae1a43462a4d6abc9fc9aaa4bb7fb4ccc09128',
        'es': '59753a514365bf3f18b4135f34024008ceb52de3f021747c0ec5420a10940042',
        'et': '5fe60acbdb80fbe37bb570fcf97cf72eace5d306fd578a501c41e967c6644f69',
        'fi': '72c677f3063ed5d5ca3fbec764af836fda3ac1a418caeac018d343faca30f8ff',
        'fr': 'a2d23fbea52dfae73e640303efb9d82c651875c5ae522d4d7ae1e1630c55debf',
        'ga': '4c90e831d124d0429bd3704739934948742417e80674d5af2517fd182fbb2007',
        'hr': '1b711c113659106c871d4a7b7252e35b629a8df71f7911a2d71e0840d52bc6d8',
        'hu': '8bdba063714e08ea3a41320eba499e8e0886f8cca4081b58d987ca6a75b3ea02',
        'it': '0ab9072e835775b81e483325d9062c0d2108fdc5c0e852ec57495f1ae8d92586',
        'lt': '54b7a38c33abac5e74d6a8a06d387ee2eaf60c65a8e5fad92c2fb61bd60c1d01',
        'lv': '622b7269396bc8aea99028678939f9bd853cdb5e74798af8d54185790674f919',
        'mt': 'de9f83090f22751b1a0576743dc448fb67fe9ff41cac53b2262b2ed91f6bdcb4',
        'nl': 'c0558402ef6f6f1a7008ab3d1975c96f9fbc5dea20bf2dcd15f289eb5a2b1350',
        'pl': 'a71fdda5443c31ff5fe54e1ad24324c88acda6e880deed9fa1664094e9ea2556',
        'pt': '3baf40ec45e997747cf1f17f37702797cee7357c3d6601712c261386fe8a9255',
        'ro': 'ddd2de2ed6e245d108d61fcf462246bd03c3ce175ef6a973d650c4fe518d9afd',
        'sk': '36a1af0dea3f9eef7335b8d294d0555da788396af52857d0e76ff51ba87dfe5f',
        'sl': 'b4fccee720e332f50b3a0c7eecf543056908679f2c43ca9143e5cbd300bbe121',
        'sv': '55758c3b902c3cba1eb9fe75cb6038475b243b86ed704c9abf43b3286eb3db3e',
    },
};
