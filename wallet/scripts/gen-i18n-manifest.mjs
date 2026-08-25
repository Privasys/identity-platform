#!/usr/bin/env node
// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Generate src/i18n/manifest.ts from the locale packs on disk.
 *
 * The manifest is the trust root for downloaded packs (see i18n/packs.ts):
 * it pins a SHA-256 per pack, and the wallet refuses any pack that does not
 * match. Because the digest list ships inside the JS bundle, this script MUST
 * run whenever a locale file changes, and the result MUST be committed.
 * src/__tests__/i18n-manifest.test.ts fails the build if it is stale.
 *
 * The manifest VERSION is derived from the pack contents, not from the app
 * version: app.config.ts uses `runtimeVersion: { policy: 'appVersion' }`, so
 * an EAS Update can change copy while the app version stands still. Deriving
 * the version from content means the pack URL moves exactly when the copy
 * moves, and never otherwise.
 *
 *   npm run i18n:manifest
 */

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const LOCALES_DIR = resolve(HERE, '..', 'src', 'i18n', 'locales');
const MANIFEST_PATH = resolve(HERE, '..', 'src', 'i18n', 'manifest.ts');

/** en-GB is compiled into the bundle, so it is never a downloadable pack. */
const BUNDLED = 'en-GB';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/**
 * Refuse to hash a pack containing CRLF.
 *
 * These digests are the trust root, and they are taken over raw bytes. A
 * Windows checkout with core.autocrlf=true hands this script CRLF files, so
 * the manifest it writes pins bytes that exist on exactly one machine: git
 * stores LF, CI serves LF, and every pack then fails verification for every
 * user. The failure is silent on device, because a rejected pack simply
 * leaves the wallet on English.
 *
 * .gitattributes pins these files to LF, so reaching this error means the
 * working tree predates it. `git add --renormalize wallet/src/i18n/locales`
 * fixes it.
 */
function assertLf(tag, buf) {
    if (buf.includes(13)) {
        console.error(
            `${tag}.json contains CRLF. The manifest hashes raw bytes, so this would ` +
            `pin digests that only reproduce on this machine and every pack would ` +
            `fail verification on device.\n` +
            `Fix: git add --renormalize wallet/src/i18n/locales && git checkout -- wallet/src/i18n/locales`,
        );
        process.exit(1);
    }
}

export function buildManifest() {
    const files = readdirSync(LOCALES_DIR)
        .filter((f) => f.endsWith('.json'))
        .map((f) => f.replace(/\.json$/, ''))
        .filter((tag) => tag !== BUNDLED)
        .sort();

    const digests = {};
    for (const tag of files) {
        assertLf(tag, readFileSync(join(LOCALES_DIR, `${tag}.json`)));
        // Digest the bytes on the wire, which is the file verbatim. Any
        // re-serialising here would silently break the device-side check.
        digests[tag] = sha256(readFileSync(join(LOCALES_DIR, `${tag}.json`)));
    }

    // Version = a digest over the (tag, digest) pairs, so it changes if any
    // pack changes, if a pack is added, or if one is removed.
    const version = sha256(
        Object.entries(digests).map(([t, d]) => `${t}:${d}`).join('\n'),
    ).slice(0, 16);

    return { version, digests };
}

export function renderManifest({ version, digests }) {
    const entries = Object.entries(digests)
        .map(([tag, digest]) => `        '${tag}': '${digest}',`)
        .join('\n');

    return `// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * GENERATED FILE — do not edit by hand.
 * Regenerate with \`npm run i18n:manifest\` after changing any locale pack.
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
    version: '${version}',
    digests: {
${entries || '        // no packs yet'}
    },
};
`;
}

// Only write when run directly, so the test can import and compare.
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
    const manifest = buildManifest();
    writeFileSync(MANIFEST_PATH, renderManifest(manifest), 'utf8');
    const n = Object.keys(manifest.digests).length;
    console.log(`i18n manifest ${manifest.version}: ${n} pack${n === 1 ? '' : 's'}`);
}
