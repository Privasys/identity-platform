// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Assert the built iOS entitlements still say what app.config.ts thinks.
 *
 * Written after a near miss. The Apple account transfer changed the app's App ID
 * prefix, so every keychain item an installed wallet holds — profile,
 * credentials, sovereign root, and the Secure Enclave keys themselves — sits
 * under a group the new build could no longer reach. The remedy is to declare
 * both prefixes. That was declared correctly in app.config.ts and then thrown
 * away: modules/passkey-provider/app.plugin.js ASSIGNED
 * `keychain-access-groups` rather than merging into it, so two of the four
 * entries vanished somewhere between the config and the binary. Nothing failed.
 * The config read correctly, the build would have succeeded, and the first
 * symptom would have been users opening an empty wallet.
 *
 * So this checks the RESOLVED config, after every plugin has run, which is the
 * only place that mistake is visible.
 *
 *   node scripts/check-ios-entitlements.mjs
 */

import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

// The legacy groups are gated: Apple refuses to sign a profile carrying a
// prefix the team no longer owns, so they are only declared once Apple has
// added the previous prefix to the App ID. This check follows the same flag, so
// it verifies whichever shape the build is actually meant to produce.
const LEGACY = process.env.WALLET_LEGACY_KEYCHAIN === '1';

/** Groups the main app must carry, and why each one is load-bearing. */
const REQUIRED_MAIN = [
    // Where this build reads and writes.
    '$(AppIdentifierPrefix)org.privasys.wallet',
    '$(AppIdentifierPrefix)org.privasys.shared',
    // Where every build before the Apple transfer wrote. Without these an
    // updated app cannot see an existing wallet.
    ...(LEGACY ? ['3V8YCKN438.org.privasys.wallet', '3V8YCKN438.org.privasys.shared'] : []),
];

/** Both extensions share only the notification-key group. */
const REQUIRED_EXTENSION = [
    '$(AppIdentifierPrefix)org.privasys.shared',
    ...(LEGACY ? ['3V8YCKN438.org.privasys.shared'] : []),
];

function resolvedConfig() {
    // The CLI is invoked through node rather than npx: Windows refuses to
    // spawn a .cmd without a shell, and going through a shell to work around
    // that would mean quoting arguments differently per platform.
    const out = execFileSync(
        process.execPath,
        [require.resolve('expo/bin/cli'), 'config', '--type', 'introspect', '--json'],
        { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, env: { ...process.env, STAGE: process.env.STAGE ?? 'production' } },
    );
    // `expo config` prints progress before the JSON on some versions.
    const start = out.indexOf('{');
    if (start < 0) throw new Error('expo config produced no JSON');
    return JSON.parse(out.slice(start));
}

function check(label, actual, required, errors) {
    const groups = Array.isArray(actual) ? actual : [];
    for (const want of required) {
        if (!groups.includes(want)) errors.push(`${label}: missing ${want}`);
    }
    return groups;
}

const config = resolvedConfig();
const errors = [];

const main = check('main app', config.ios?.entitlements?.['keychain-access-groups'], REQUIRED_MAIN, errors);

// Independent of the flag: a plugin that ASSIGNS rather than merges drops
// whatever app.config.ts declared, and the shared group is the entry that
// disappears first. It is what the notification key lives under.
if (!main.includes('$(AppIdentifierPrefix)org.privasys.shared')) {
    errors.push('main app: the shared group is gone, so a plugin overwrote the list');
}

// The FIRST entry is the default group for new keychain items. If a legacy
// group ever sorts first, new data starts landing under the old prefix, which
// is the bug's mirror image and just as quiet.
if (main.length > 0 && main[0] !== '$(AppIdentifierPrefix)org.privasys.wallet') {
    errors.push(`main app: default group is ${main[0]}, expected $(AppIdentifierPrefix)org.privasys.wallet`);
}

const extensions = config.extra?.eas?.build?.experimental?.ios?.appExtensions ?? [];
if (extensions.length !== 2) {
    errors.push(`expected 2 app extensions, found ${extensions.length}`);
}
for (const ext of extensions) {
    check(ext.targetName, ext.entitlements?.['keychain-access-groups'], REQUIRED_EXTENSION, errors);
}

// The second half of the same mistake, which the entitlement check above
// cannot see. Declaring a keychain group correctly is useless if the native
// code then ASKS for a different one: iOS answers errSecMissingEntitlement
// and the caller usually reads that as "no such item".
//
// The passkey extension asked for "group.org.privasys.wallet", an app group
// identifier rather than a keychain group, and no app group is entitled
// anywhere in the project. Every SecItem call failed, so choosing Privasys
// Wallet in the OS passkey sheet did nothing at all, silently, in a shipped
// build (2026-09-08).
//
// A group is legitimate if an entitlement grants it, with or without the
// $(AppIdentifierPrefix) prefix: iOS resolves an unprefixed group against the
// entitled list, which is what the notification-service extension relies on.
const entitledSuffixes = new Set(
    [...REQUIRED_MAIN, ...REQUIRED_EXTENSION].map((g) => g.replace('$(AppIdentifierPrefix)', '')),
);

function swiftFiles(dir) {
    const out = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === 'node_modules' || entry.name === 'build') continue;
        const full = join(dir, entry.name);
        if (entry.isDirectory()) out.push(...swiftFiles(full));
        else if (entry.name.endsWith('.swift')) out.push(full);
    }
    return out;
}

for (const file of swiftFiles('modules')) {
    const src = readFileSync(file, 'utf8');
    // Every access group in this codebase reaches kSecAttrAccessGroup through a
    // named constant, so the declarations are what to check.
    for (const m of src.matchAll(/(?:let|var)\s+\w*[Kk]eychainGroup\w*\s*(?::\s*String\s*)?=\s*"([^"]+)"/g)) {
        const asked = m[1].replace('$(AppIdentifierPrefix)', '');
        if (!entitledSuffixes.has(asked)) {
            errors.push(
                file + ' asks the keychain for group "' + m[1] + '", which no ' +
                'entitlement grants (entitled: ' + [...entitledSuffixes].join(', ') + ')',
            );
        }
    }
}

if (errors.length > 0) {
    console.error('iOS entitlements are not what app.config.ts declares:');
    for (const e of errors) console.error(`  ✗ ${e}`);
    console.error('\nTwo usual causes. A config plugin that ASSIGNS keychain-access-groups');
    console.error('instead of merging into them (see modules/passkey-provider/app.plugin.js),');
    console.error('or native code asking for a group no entitlement grants, which iOS answers');
    console.error('with errSecMissingEntitlement and callers routinely misread as an empty');
    console.error('keychain rather than a permissions failure.');
    process.exit(1);
}

console.log('iOS entitlements ok');
console.log(`  main app:  ${main.join(', ')}`);
for (const ext of extensions) {
    console.log(`  ${ext.targetName}: ${(ext.entitlements['keychain-access-groups'] ?? []).join(', ')}`);
}
