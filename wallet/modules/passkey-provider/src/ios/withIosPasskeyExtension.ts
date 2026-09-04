// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * iOS config plugin: adds an ASCredentialProviderExtension target.
 *
 * This registers the Privasys Wallet as a passkey provider on iOS 17+.
 * When a website calls navigator.credentials.get() with an RP ID the
 * wallet recognises, iOS routes the request to our extension, which:
 * 1. Verifies enclave attestation via RA-TLS
 * 2. Shows a compact attestation summary UI
 * 3. Signs the WebAuthn challenge with the hardware-bound key
 *
 * The extension shares a keychain group with the main app for credential
 * and key access.
 */

import {
    ConfigPlugin,
    withXcodeProject,
    withInfoPlist,
    withEntitlementsPlist,
    IOSConfig,
} from 'expo/config-plugins';
import * as path from 'path';

const EXTENSION_NAME = 'PasskeyProvider';
const EXTENSION_BUNDLE_SUFFIX = '.PasskeyProvider';

/**
 * Add the ASCredentialProviderExtension target to the Xcode project.
 */
export const withIosPasskeyExtension: ConfigPlugin = (config) => {
    // 1. Add entitlements for shared keychain + credential provider
    config = withEntitlementsPlist(config, (mod) => {
        const bundleId = mod.modResults['com.apple.application-identifier']
            ?? IOSConfig.BundleIdentifier.getBundleIdentifier(mod)
            ?? 'org.privasys.wallet';

        // Shared keychain group for main app + extension credential access.
        //
        // MERGED, not assigned. This used to overwrite the key outright, which
        // silently discarded anything app.config.ts declared — including the
        // legacy 3V8YCKN438 groups added after the Apple account transfer to
        // keep existing wallets readable. The config looked right, the built
        // app was missing two entries, and nothing said so.
        //
        // Order is preserved because the FIRST entry is the default group for
        // new keychain items: whatever app.config.ts puts first stays first,
        // and this only appends what is genuinely absent.
        const required = [
            `$(AppIdentifierPrefix)${bundleId}`,
            `$(AppIdentifierPrefix)org.privasys.shared`,
        ];
        const existing = Array.isArray(mod.modResults['keychain-access-groups'])
            ? (mod.modResults['keychain-access-groups'] as string[])
            : [];
        mod.modResults['keychain-access-groups'] = [
            ...existing,
            ...required.filter((group) => !existing.includes(group)),
        ];

        return mod;
    });

    // 2. Enable Associated Domains (for webcredentials passkey matching)
    config = withEntitlementsPlist(config, (mod) => {
        const domains = (mod.modResults['com.apple.developer.associated-domains'] as string[]) ?? [];
        const passkey = 'webcredentials:privasys.id';
        if (!domains.includes(passkey)) {
            mod.modResults['com.apple.developer.associated-domains'] = [...domains, passkey];
        }
        return mod;
    });

    // 3. NSExtension for credential provider UI requires a separate Xcode
    //    extension target. Adding it to the main app Info.plist causes Apple
    //    validation to reject the IPA. TODO: add proper extension target.

    // 4. Add extension target placeholder to Xcode project
    config = withXcodeProject(config, (mod) => {
        const project = mod.modResults;
        const bundleId = IOSConfig.BundleIdentifier.getBundleIdentifier(mod)
            ?? 'org.privasys.wallet';
        const extensionBundleId = bundleId + EXTENSION_BUNDLE_SUFFIX;

        // Note: Full Xcode target addition requires complex PBX manipulation.
        // For EAS Build, the extension source files are placed in the ios/
        // directory and the target is configured in the Xcode workspace.
        // This plugin adds the entitlements and Info.plist configuration;
        // the actual .xcodeproj target must be added via EAS build hooks
        // or manually after the first prebuild.

        // Add a build comment to mark that the extension is expected
        console.log(
            `[passkey-provider] Configured entitlements for ${extensionBundleId}. ` +
            `Extension target "${EXTENSION_NAME}" must be added to the Xcode project ` +
            `via EAS build hooks or the Xcode IDE.`
        );

        return mod;
    });

    return config;
};
