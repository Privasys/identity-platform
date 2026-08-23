#!/usr/bin/env node
// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Build the static tree that privasys.id serves at /i18n/.
 *
 *   npm run i18n:packs            -> dist-i18n/<version>/<tag>.json
 *   npm run i18n:packs -- --out X -> X/<version>/<tag>.json
 *
 * The wallet fetches `${IDP}/i18n/${manifest.version}/${tag}.json` and
 * refuses any body whose SHA-256 is not the one pinned in the bundle
 * (i18n/packs.ts). So the bytes served must be the bytes hashed, exactly.
 * This script copies the locale files verbatim and then re-hashes what it
 * wrote, comparing against the committed manifest. A mismatch is fatal:
 * shipping a tree that fails verification does not degrade gracefully, it
 * silently pins every user to English.
 *
 * Deliberately generated from src/i18n/locales rather than vendored into
 * the websites repo. Same files, same repo, same CI run as the manifest
 * means there is no window in which the two can drift.
 *
 * The output path is versioned by content digest, so deploys are ADDITIVE.
 * An app build in the wild asks for the version it was compiled against;
 * deleting old version directories strands those users on English for any
 * language they have not already cached. See the deploy workflow.
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const LOCALES_DIR = resolve(HERE, '..', 'src', 'i18n', 'locales');
const MANIFEST_PATH = resolve(HERE, '..', 'src', 'i18n', 'manifest.ts');

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function parseArgs(argv) {
    const out = { outDir: resolve(HERE, '..', 'dist-i18n') };
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === '--out') {
            const v = argv[++i];
            if (!v) throw new Error('--out requires a path');
            out.outDir = resolve(process.cwd(), v);
        }
    }
    return out;
}

/**
 * Read the committed manifest.
 *
 * Parsed out of the emitted TypeScript rather than imported: this script
 * runs under plain node with no transpiler, and the manifest is a generated
 * literal whose shape we control. If the shape ever changes, this throws
 * loudly rather than silently producing an unverified tree.
 */
function readManifest() {
    const src = readFileSync(MANIFEST_PATH, 'utf8');

    const version = src.match(/version:\s*'([0-9a-f]{16})'/)?.[1];
    if (!version) throw new Error(`could not parse version from ${MANIFEST_PATH}`);

    const block = src.match(/digests:\s*\{([\s\S]*?)\}/)?.[1];
    if (!block) throw new Error(`could not parse digests from ${MANIFEST_PATH}`);

    const digests = {};
    for (const m of block.matchAll(/'?([A-Za-z-]+)'?:\s*'([0-9a-f]{64})'/g)) {
        digests[m[1]] = m[2];
    }
    if (!Object.keys(digests).length) throw new Error('manifest lists no packs');

    return { version, digests };
}

function main() {
    const { outDir } = parseArgs(process.argv.slice(2));
    const { version, digests } = readManifest();

    const versionDir = join(outDir, version);
    rmSync(outDir, { recursive: true, force: true });
    mkdirSync(versionDir, { recursive: true });

    const tags = Object.keys(digests).sort();
    const problems = [];

    for (const tag of tags) {
        const src = join(LOCALES_DIR, `${tag}.json`);
        let bytes;
        try {
            bytes = readFileSync(src);
        } catch {
            problems.push(`${tag}: manifest lists it but ${src} is missing`);
            continue;
        }

        // Parse to catch a corrupt file before it reaches a device, where the
        // failure surfaces as a language that silently refuses to load.
        try {
            JSON.parse(bytes.toString('utf8'));
        } catch (e) {
            problems.push(`${tag}: not valid JSON (${e.message})`);
            continue;
        }

        const dest = join(versionDir, `${tag}.json`);
        writeFileSync(dest, bytes);

        // Re-hash what was actually written, not what was read. This is the
        // check that would catch a truncated write or a stray transform.
        const got = sha256(readFileSync(dest));
        if (got !== digests[tag]) {
            problems.push(`${tag}: served digest ${got} != manifest ${digests[tag]}`);
        }
    }

    if (problems.length) {
        console.error('i18n pack build FAILED:');
        for (const p of problems) console.error(`  - ${p}`);
        console.error('\nRun `npm run i18n:manifest` and commit the result.');
        process.exit(1);
    }

    console.log(`i18n packs: ${tags.length} locales at version ${version}`);
    console.log(`  ${versionDir}`);
    console.log(`  ${tags.join(' ')}`);
}

main();
