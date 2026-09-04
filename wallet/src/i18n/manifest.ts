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
    version: 'df7dec70b86a92bf',
    digests: {
        'bg': '4b338b92b38b33db41fcfc1cb06a4c99c8470ade7caf2b91f3818543aa7a50bb',
        'cs': '99af0d0b4e25e14cdd4a8fabbb9fc33f69f28eaa8b7c26f6483dfa042362bcd2',
        'cy': '04c09d0bb8300d8f876058d13ddd41dbd597db6fd7f87c7c504a03c0efea1525',
        'da': '27d7980b3b9f6ae7e2f7af4e2facce8604968778a4b56a63d5588848648917fb',
        'de': '61825471b384abf10d95adfddeb98db449e42b8712202a92ab3525ec6047fb4f',
        'el': '65f55b9e2b59787feb68604d642b355e2ef4960e4dfb44ed89a6f4ad25ba3a36',
        'es': '1d00b69065d86af1f267f4af3f85f84a795aeae17f4b0c636008bff060ca2909',
        'et': '23d25100c12ae64f90c24eb3cad25de316761a1acaea2dbf6b38aa7e5256186c',
        'fi': 'd8820d348416a60f663121cf756faa357258e6186be43ddedf32a0a3e0a8cfa4',
        'fr': '66c1a7cd2b63cb042fe4e489f8f6c238853ea38fca61919321e377783f0498ec',
        'ga': '2e61b628a45f251f3fae116aca6b825ee53cd244ad8ef96a8a6ac42966d71bd9',
        'hr': 'adb3256e68a7293bc8dfef7940da5a1e5db8c05577fc2b262cc7f83442487c03',
        'hu': '2124e8ebf53638c3212669ba786a2f0f518835451a647b4ab4a15fe633cbce8c',
        'it': '851f563a0c7885568e52d3c290056e0cf621a1cef249eefe8faf52f8d799cce9',
        'lt': '11dd5ae0441143666f8240f2284b4f221d81dcae7e9701df7cb06e5e05201c12',
        'lv': 'c520e05d181730a3cdece61330e8a3af182a6f6d3eef073890b9b60221b7891e',
        'mt': '95de200b3777dd8ad601e609e1f64ccb25abc2fc96844f6e2a081300f1768382',
        'nl': '4fc4e4cfd8112a3cee2ee4c8a0eb0bf15420e6d93027e21300a990228c926f2e',
        'pl': '59aa947fedc6cb4e9b35cbe5eb4213890cd61561a7183a11077df26b8db0ab67',
        'pt': '9d4f1ff69d8a4b9b530de14200e9a73a2d5290527a6a685a0ddf4d9c28d2d0b2',
        'ro': '56bdf61ab03e52f98bdf20dba02601e27b2c2c992a8019bf6a1d60e3b6ac2e8f',
        'sk': '701a89855c030048c239e6ce53028587c5204c9e89ced8f96aacd28586430917',
        'sl': '7ecb0712c49e9613f8d0919c9324d49e536c73927b933a396d48f4e7f7e9c075',
        'sv': '848cd0ceca87413b51f18b967fe814586f4da2fe135b865337234cbdd6dc3ee6',
    },
};
