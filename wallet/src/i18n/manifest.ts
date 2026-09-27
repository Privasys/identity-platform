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
    version: '4db1b86a117e888d',
    digests: {
        'bg': '0249bff5bc97cdcf9c0b7b952efc68bac96f5bf3b5cc1f2f570fcb935dde4511',
        'cs': '88e4eaaf76ef2f6f6b7793f8a395d833aff19faebbd80d8581d2e0f51634ba5f',
        'cy': '56fb9d423f830ae6d4a5c59a8cac3c646a7d96d7d5b9e9e846570de6373a1c28',
        'da': '538517c5b96379ec3058cfceeb5248375933d7b37da9e1a8b877de32d69d059b',
        'de': '2c02e546439ee77753d0642cf49ae3a749509c4bcb7e852e92ca2d355a35d3f6',
        'el': '4dcc9dc9daac8f213b56a44699af4ee88c07701213cb0f93d34c1a9c037e8d9f',
        'es': '5219c58617578de104e28602f4601a081a59f7b467cf415295c09a2a76a8226c',
        'et': 'bbb85845ddab6437f3d0126a976d1abc8d96836a5a70c4bf91c66199881a819f',
        'fi': '45b78a8b4dd67591ee1d190a5dca9e0ffa82f274b7f57f90a487700e15a3e28e',
        'fr': '21c62c410aad6ca3a9d9dce599f5ac039c4848c5bfe41241d02373e8b8537595',
        'ga': '8d1aa0ebc5b8801617210bddca48fcb99e52a8bc2dfca9a5a46d5095e23db032',
        'hr': 'f85f4d7dae891c594ac03670439df7c980938e16d329d8ffe42d3816771e919b',
        'hu': '04ea1160e8705764235970d455fea528235bc1987d5cd240b63028b835748610',
        'it': 'a706afefe2123408b83ad727f946ff0a0f7e30cc1291543f9edc203522ff4eb4',
        'lt': '230fac01aab440d76f8d38e6647ae8d406c5117720e51418cca728f493b370dd',
        'lv': '1e505f3b60fa799778354337b7bf1c44509b554dd7695333239b342fb021bb0e',
        'mt': '6fbec2ced9e226be095162d04fdc19904365fe8943cab9f74781629ca30e3bb9',
        'nl': 'cc34cd9dc74e5d10818dfce62b0f009c1fba9095eeb73190491c80a9b4f658bc',
        'pl': 'aaf60e21fe7d99be462d9366ff11a137885e482c20a0f0d3621708db53587dbe',
        'pt': '01f3f1a84bc1f67b92bb4e579e2d98524a36913c3f5f34ef8f0eeea089753789',
        'ro': '60f28a1e4ca9c238eda37f5902e5af8e636d82687607493afb8ff136776c407f',
        'sk': '5a898ab1f9a57e61c71f63b8d2d861bac8992fd781f803316448c03e26c3a804',
        'sl': '1d9bd99fc70ffc82468b8cad7607b8962711561a87b5b4400cf4bac212225120',
        'sv': '82202460e36dbe0d9d82ca9c80b2733251d5d77f3920f2028edacea804712a86',
    },
};
