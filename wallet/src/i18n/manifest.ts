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
    version: '7963d0216963ab56',
    digests: {
        'bg': '5df2174d47f011a113ab60ad04ea674badb92f421ebadfb12e814d6116902450',
        'cs': '963afd8867bff5a412c0e3d710edb8d335aab0c546db6c4c5b6443e0de66f66e',
        'cy': 'bf2a796f33e9200d342ec19ee0d900dde6b81862d7217617f8ce5c392b8e9f21',
        'da': '3fbd24288134cf260eee2255b0be0cd0059e579f25073c14ace1a2ab0aa9c367',
        'de': '68089a5b265cff0b02879c80f8622dba529cc94f96cdd4d60819fa9139ad1b41',
        'el': '13c5649b89ef3da41e34a1d1d79bcd21c5a9a0e50f62af8edc76dc5a461e441b',
        'es': 'a6c2949f384e04a0c67d0b6856fdd3afb7dc690a09e8622ba4b86ef1e00277dc',
        'et': '7b9559f514889b96b7143400e466cd19f79127c5c071bc2cc323833e2b4ffe3e',
        'fi': '63705fc6bc73005a5ccd77cedac35774312156349bbe6f4a0bb535aaebbbd52e',
        'fr': '5763f243e2b7fffa7958509aa1efa9544e43531d3ddad7761e8e84b9d476451d',
        'ga': '9cfcef7a383a7894d8f30b1f2e1c0f011ed06e61ac95086b1b879d383ba8cedc',
        'hr': 'f48506788ea90ef51be54fa7a80e3f8a367e49e0034da56c7377a89498b19545',
        'hu': '9e3fcbc76c643e70ff3a2558129228305b6c111b604b2a4e2c172ac1e1a92af1',
        'it': 'fb65e8bc6122d112af22ebdd08c6b7d57d8269e68de49b534fe942b29d6123f6',
        'lt': '0659638221dd8c3706a29fe90fdb6cdc43cc0d608a857cabe23f6250678d5a70',
        'lv': 'c96f85f4911ba5e7c924708819408344131159cd095025ec523f0013c257de55',
        'mt': 'da7dca75e669c295c6026018371cc96d7a69eb6aa332b99a9fc2798628433c6c',
        'nl': '6ae441f420609bcc81c7f7de4ff8ed3c6091a712ed6f04d4ac9fb726f8435bab',
        'pl': '52e7a04cb6d9bc18e03c90d87e42423f8a91658268c1177061a7e4323ac0f67a',
        'pt': '65bb14b12a22e9863be3a849a38da08bd24eb8addd7e0ab690f488ad59f6de33',
        'ro': 'd6bae5c3b3550c4c2c44a71ccd2d7cbcc4729491902ceaa84b74e225371f8cf0',
        'sk': '80d3570d89ad4ca69825e7fa3021af472cbac9159a5db0f071ec86113ac1d3bc',
        'sl': '93e70ee371b5e9d7b532541f490697fc5bfd390e7b8c2f750b9677bb3d1ed7ff',
        'sv': '38a806367b82a30e49a05ff753eac4101f8f0b7b5ee82750b950158e3d892521',
    },
};
