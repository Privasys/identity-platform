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

if (errors.length > 0) {
    console.error('iOS entitlements are not what app.config.ts declares:');
    for (const e of errors) console.error(`  ✗ ${e}`);
    console.error('\nA config plugin that ASSIGNS keychain-access-groups instead of merging');
    console.error('into them is the usual cause. See modules/passkey-provider/app.plugin.js.');
    process.exit(1);
}

console.log('iOS entitlements ok');
console.log(`  main app:  ${main.join(', ')}`);
for (const ext of extensions) {
    console.log(`  ${ext.targetName}: ${(ext.entitlements['keychain-access-groups'] ?? []).join(', ')}`);
}
