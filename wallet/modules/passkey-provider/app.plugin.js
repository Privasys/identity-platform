// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// Expo config plugin — registers the wallet as a system passkey provider.
// Written in plain JS because config plugins are evaluated by Node.js at
// prebuild time, before metro/TypeScript compilation.

const {
    withPlugins,
    withEntitlementsPlist,
    withInfoPlist,
    withAndroidManifest,
    withXcodeProject,
    withDangerousMod,
    AndroidConfig,
    IOSConfig,
} = require('expo/config-plugins');
const path = require('path');
const fs = require('fs');

const SERVICE_CLASS =
    'org.privasys.wallet.passkey.PrivasysCredentialProviderService';

const EXTENSION_NAME = 'PasskeyProvider';
const EXTENSION_BUNDLE_ID_SUFFIX = '.PasskeyProvider';

// ── iOS: main app entitlements ────────────────────────────────────────

function withIosMainAppEntitlements(config) {
    // Shared keychain group
    config = withEntitlementsPlist(config, (mod) => {
        const bundleId =
            mod.modResults['com.apple.application-identifier'] ||
            IOSConfig.BundleIdentifier.getBundleIdentifier(mod) ||
            'org.privasys.wallet';

        // MERGED, not assigned, the same way the associated-domains block
        // below does it. Assigning outright silently discarded anything
        // app.config.ts declared, which after the Apple account transfer meant
        // dropping the legacy 3V8YCKN438 groups that keep an existing wallet
        // readable. The config looked correct and the built app was missing
        // two entries, with nothing anywhere to say so.
        //
        // Order is preserved: the FIRST entry is the default group for new
        // keychain items, so whatever app.config.ts puts first stays first and
        // this only appends what is genuinely absent.
        const required = [
            `$(AppIdentifierPrefix)${bundleId}`,
            '$(AppIdentifierPrefix)org.privasys.shared',
        ];
        const existing = Array.isArray(mod.modResults['keychain-access-groups'])
            ? mod.modResults['keychain-access-groups']
            : [];
        mod.modResults['keychain-access-groups'] = [
            ...existing,
            ...required.filter((group) => !existing.includes(group)),
        ];
        return mod;
    });

    // Associated domains (webcredentials for passkey matching)
    config = withEntitlementsPlist(config, (mod) => {
        const domains =
            mod.modResults['com.apple.developer.associated-domains'] || [];
        if (!domains.includes('webcredentials:privasys.id')) {
            mod.modResults['com.apple.developer.associated-domains'] = [
                ...domains,
                'webcredentials:privasys.id',
            ];
        }
        return mod;
    });

    // Credential provider entitlement (required on main app for the extension)
    config = withEntitlementsPlist(config, (mod) => {
        mod.modResults[
            'com.apple.developer.authentication-services.autofill-credential-provider'
        ] = true;
        return mod;
    });

    return config;
}

// ── iOS: copy extension source files ──────────────────────────────────

function withIosExtensionFiles(config) {
    return withDangerousMod(config, [
        'ios',
        async (config) => {
            const platformRoot = config.modRequest.platformProjectRoot;
            const extensionDir = path.join(platformRoot, EXTENSION_NAME);

            if (!fs.existsSync(extensionDir)) {
                fs.mkdirSync(extensionDir, { recursive: true });
            }

            const srcDir = path.join(
                config.modRequest.projectRoot,
                'modules',
                'passkey-provider',
                'ios',
            );

            // Copy Swift source, Info.plist, and entitlements
            const files = [
                ['CredentialProviderViewController.swift', 'CredentialProviderViewController.swift'],
                ['PasskeyProvider-Info.plist', 'Info.plist'],
                ['PasskeyProvider.entitlements', `${EXTENSION_NAME}.entitlements`],
            ];

            for (const [src, dst] of files) {
                const srcFile = path.join(srcDir, src);
                if (fs.existsSync(srcFile)) {
                    fs.copyFileSync(srcFile, path.join(extensionDir, dst));
                }
            }

            return config;
        },
    ]);
}

// ── iOS: add extension target to Xcode project ───────────────────────

function withIosExtensionTarget(config) {
    return withXcodeProject(config, async (config) => {
        const project = config.modResults;
        const mainBundleId =
            config.ios?.bundleIdentifier || 'org.privasys.wallet';
        const extBundleId = `${mainBundleId}${EXTENSION_BUNDLE_ID_SUFFIX}`;

        // Prevent duplicate target if plugin runs twice
        const existingTargets = project.pbxNativeTargetSection();
        for (const key in existingTargets) {
            const t = existingTargets[key];
            if (
                typeof t === 'object' &&
                t.name === `"${EXTENSION_NAME}"`
            ) {
                return config;
            }
        }

        // Create the extension target
        const target = project.addTarget(
            EXTENSION_NAME,
            'app_extension',
            EXTENSION_NAME,
            extBundleId,
        );

        // Add an empty PBXGroup so Xcode resolves file paths
        // relative to the extension folder.
        const group = project.addPbxGroup(
            [],
            EXTENSION_NAME,
            EXTENSION_NAME,
        );
        const mainGroup =
            project.getFirstProject().firstProject.mainGroup;
        project.addToPbxGroup(group.uuid, mainGroup);

        // Add source build phase — use full path from project root
        project.addBuildPhase(
            [`${EXTENSION_NAME}/CredentialProviderViewController.swift`],
            'PBXSourcesBuildPhase',
            'Sources',
            target.uuid,
        );

        // Add frameworks build phase
        project.addBuildPhase(
            [],
            'PBXFrameworksBuildPhase',
            'Frameworks',
            target.uuid,
        );

        // Add resources build phase
        project.addBuildPhase(
            [],
            'PBXResourcesBuildPhase',
            'Resources',
            target.uuid,
        );

        // Configure build settings for the extension
        const targetObj =
            project.pbxNativeTargetSection()[target.uuid];
        if (targetObj) {
            const configListUuid = targetObj.buildConfigurationList;
            const configLists = project.pbxXCConfigurationList();
            const configList = configLists[configListUuid];

            if (configList && configList.buildConfigurations) {
                const allConfigs =
                    project.pbxXCBuildConfigurationSection();

                for (const { value } of configList.buildConfigurations) {
                    const bc = allConfigs[value];
                    if (!bc || !bc.buildSettings) continue;

                    Object.assign(bc.buildSettings, {
                        INFOPLIST_FILE: `"${EXTENSION_NAME}/Info.plist"`,
                        CODE_SIGN_ENTITLEMENTS: `"${EXTENSION_NAME}/${EXTENSION_NAME}.entitlements"`,
                        SWIFT_VERSION: '5.0',
                        IPHONEOS_DEPLOYMENT_TARGET: '17.0',
                        TARGETED_DEVICE_FAMILY: '"1,2"',
                        GENERATE_INFOPLIST_FILE: 'NO',
                        CURRENT_PROJECT_VERSION: '1',
                        MARKETING_VERSION: '1.0',
                        SKIP_INSTALL: 'YES',
                        CODE_SIGN_STYLE: 'Automatic',
                        PRODUCT_BUNDLE_IDENTIFIER: `"${extBundleId}"`,
                    });
                }
            }
        }

        // Add target dependency — main app embeds the extension
        const nativeTargets = project.pbxNativeTargetSection();
        for (const key in nativeTargets) {
            const nt = nativeTargets[key];
            if (
                typeof nt === 'object' &&
                nt.productType ===
                    '"com.apple.product-type.application"'
            ) {
                project.addTargetDependency(key, [target.uuid]);
                break;
            }
        }

        return config;
    });
}

// ── Android: register CredentialProviderService in manifest ───────────

function withAndroidCredentialProvider(config) {
    config = withAndroidManifest(config, (mod) => {
        const mainApp =
            AndroidConfig.Manifest.getMainApplicationOrThrow(mod.modResults);

        const services = mainApp.service || [];
        const exists = services.some(
            (s) => s.$?.['android:name'] === SERVICE_CLASS,
        );

        if (!exists) {
            services.push({
                $: {
                    'android:name': SERVICE_CLASS,
                    'android:exported': 'true',
                    'android:permission':
                        'android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE',
                },
                'intent-filter': [
                    {
                        action: [
                            {
                                $: {
                                    'android:name':
                                        'android.service.credentials.CredentialProviderService',
                                },
                            },
                        ],
                    },
                ],
                'meta-data': [
                    {
                        $: {
                            'android:name': 'android.credentials.provider',
                            'android:resource':
                                '@xml/credential_provider_config',
                        },
                    },
                ],
            });
            mainApp.service = services;
        }

        // Register the PasskeyActivity
        const activities = mainApp.activity || [];
        const ACTIVITY_CLASS =
            'org.privasys.wallet.passkey.PasskeyActivity';
        const activityExists = activities.some(
            (a) => a.$?.['android:name'] === ACTIVITY_CLASS,
        );

        if (!activityExists) {
            activities.push({
                $: {
                    'android:name': ACTIVITY_CLASS,
                    'android:exported': 'false',
                    'android:theme': '@android:style/Theme.Translucent.NoTitleBar',
                },
            });
            mainApp.activity = activities;
        }

        return mod;
    });

    return config;
}

// ── Combined plugin ──────────────────────────────────────────────────

function withPasskeyProvider(config) {
    return withPlugins(config, [
        withIosMainAppEntitlements,
        withIosExtensionFiles,
        withIosExtensionTarget,
        withAndroidCredentialProvider,
    ]);
}

module.exports = withPasskeyProvider;
