import { execSync } from 'child_process';

import { ExpoConfig, ConfigContext } from '@expo/config';
import 'dotenv/config';

import pkg from './package.json';

const { version } = pkg;
const STAGE = process.env.STAGE || 'development';
const EXPO_PROJECT_ID =
    process.env.NX_EXPO_PROJECT_ID ??
    process.env.EXPO_PUBLIC_PROJECT_ID ??
    process.env.EAS_BUILD_PROJECT_ID ??
    '482c4a6f-fdc0-44a9-9c3e-477dd2efedbc';
// const SENTRY_DSN_URL =
//     process.env.NX_SENTRY_DSN ??
//     process.env.NX_SENTRY_URL ??
//     process.env.EXPO_PUBLIC_SENTRY_DSN ??
//     process.env.EXPO_PUBLIC_SENTRY_URL ??
//     process.env.SENTRY_DSN ??
//     process.env.SENTRY_URL;

console.log(
    `Building Privasys Wallet version ${version}. Running app.config.ts for stage: ${STAGE}...`
);

// let sentryUrl = undefined;
// try {
//     sentryUrl = SENTRY_DSN_URL ? new URL(SENTRY_DSN_URL) : undefined;
// } catch (error) {
//     console.error('Invalid Sentry DSN URL:', error);
// }

// process.env.EXPO_PUBLIC_SENTRY_AUTH_TOKEN ??= process.env.SENTRY_AUTH_TOKEN;
process.env.EXPO_PUBLIC_SENTRY_DSN ??= process.env.SENTRY_DSN;
process.env.EXPO_PUBLIC_CHALLENGE_SECRET_KEY ??= process.env.CHALLENGE_SECRET_KEY;

/**
 * The App ID prefix this app carried before it moved from the Secretarium Apple
 * account to Privasys Ltd (2026-09-04).
 *
 * A transfer was supposed to preserve it. It did not: the new prefix is
 * HLW68Z8TMZ, and Apple said so on the first delivery from the new account with
 * ITMS-90076 against all three targets, "This will result in a loss of keychain
 * access".
 *
 * That loss is not a preference or two. Keychain items are addressed by
 * `<prefix>.<group>`, so everything an installed wallet holds sits under the old
 * prefix: the profile, credentials, the auth store, the sovereign root, KYC
 * records, AND the Secure Enclave keys, which are keychain items like any other.
 * A build that cannot reach them opens as a brand-new wallet on a phone that has
 * one, and the device signing key and every FIDO2 credential are gone with it.
 *
 * So both prefixes are declared. Reads without an explicit group search every
 * entitled group, which is what lets an updated app find what the old one wrote;
 * the CURRENT prefix is listed FIRST because the first entry is the default for
 * new writes, and new data belongs under the new identity.
 *
 * ANSWERED, and the answer is no. Build 1.3.95 failed at codesign with
 * "Provisioning profile ... doesn't match the entitlements file's value for the
 * keychain-access-groups entitlement": Apple will not issue a profile carrying a
 * prefix the signing team no longer owns, so declaring the legacy groups makes
 * the app unbuildable rather than compatible.
 *
 * The entries are therefore OFF by default and gated behind an environment
 * variable. The remaining route is Apple Developer Support adding the previous
 * prefix to the org.privasys.wallet App ID; the moment they do, profiles can
 * carry it, and this becomes a one-line flip plus a rebuild rather than a
 * rediscovery of everything above.
 *
 * Until then every update loses the keychain, which is recoverable only through
 * the 24-word phrase and only for holders who kept one. That is a release
 * decision, not a build setting.
 */
const LEGACY_APP_ID_PREFIX = '3V8YCKN438.';

/**
 * Set WALLET_LEGACY_KEYCHAIN=1 once Apple has enabled the previous prefix on the
 * App ID. Enabling it before that fails the build at codesign, which is at
 * least loud; leaving it off ships an app that cannot see an existing wallet,
 * which is not.
 */
const LEGACY_KEYCHAIN_ENABLED = process.env.WALLET_LEGACY_KEYCHAIN === '1';

const legacyGroup = (name: string) =>
    LEGACY_KEYCHAIN_ENABLED ? [`${LEGACY_APP_ID_PREFIX}${name}`] : [];

/** Groups shared between the app and its extensions. */
const SHARED_KEYCHAIN_GROUPS = [
    '$(AppIdentifierPrefix)org.privasys.shared',
    ...legacyGroup('org.privasys.shared'),
];

const envConfig = {
    development: {
        name: 'Privasys Wallet Dev',
        scheme: 'privasys-wallet-dev',
        bundle: 'org.privasys.wallet',
        icon: './assets/icon.development.png',
        adaptiveIconBackgroundColor: '#F0F9FF'
    },
    preview: {
        name: 'Privasys Wallet Preview',
        scheme: 'privasys-wallet-preview',
        bundle: 'org.privasys.wallet',
        icon: './assets/icon.preview.png',
        adaptiveIconBackgroundColor: '#F0FFF4'
    },
    production: {
        name: 'Privasys Wallet',
        scheme: 'privasys-wallet',
        bundle: 'org.privasys.wallet',
        icon: './assets/icon.production.png',
        adaptiveIconBackgroundColor: '#FFFFFF'
    }
};

const config = envConfig[STAGE as keyof typeof envConfig];

function getCommitHash(): string {
    if (process.env.EAS_BUILD_GIT_COMMIT_HASH) return process.env.EAS_BUILD_GIT_COMMIT_HASH;
    try {
        return execSync('git rev-parse HEAD', { encoding: 'utf-8' }).trim();
    } catch {
        return '';
    }
}

export default (context: ConfigContext): ExpoConfig => {
    const { config: defaultConfig } = context;
    const finalConfig: ExpoConfig = {
        ...defaultConfig,
        name: config.name,
        description:
            'Privasys Wallet is a digital identity wallet. Connect to services that prove their integrity before you prove yours.',
        slug: 'privasys-wallet',
        owner: 'privasys',
        icon: config.icon,
        version: version,
        splash: {
            image: './assets/splash-blank.png',
            resizeMode: 'contain',
            backgroundColor: '#FFFFFF'
        },
        assetBundlePatterns: ['**/*'],
        userInterfaceStyle: 'light',
        orientation: 'default',
        updates: {
            fallbackToCacheTimeout: 0,
            checkAutomatically: 'WIFI_ONLY',
            url: `https://privasys.id/updates/${EXPO_PROJECT_ID}`
        },
        newArchEnabled: true,
        jsEngine: 'hermes',
        runtimeVersion: { policy: 'appVersion' },
        scheme: config.scheme,
        ios: {
            supportsTablet: true,
            requireFullScreen: true,
            bundleIdentifier: config.bundle,
            infoPlist: {
                ITSAppUsesNonExemptEncryption: false,
                CFBundleAllowMixedLocalizations: true,
                // Shown when reading a passport/ID chip over NFC (KYC flow). The
                // NFC reader-session *entitlement* is added with the device-tested
                // chip-read implementation (it needs an Apple App ID capability).
                NFCReaderUsageDescription:
                    'Privasys reads your ID document chip to verify your identity. The data stays on your device.',
                // REQUIRED for reading the passport/ID (eMRTD) chip: iOS only lets
                // the app SELECT these ISO-7816 application IDs. Without this the
                // chip is never detected even with a correct BAC key.
                'com.apple.developer.nfc.readersession.iso7816.select-identifiers': [
                    'A0000002471001', // eMRTD LDS1 (ICAO 9303 passport application)
                    'A0000002472001', // eMRTD LDS2
                ],
                // A manual CFBundleURLTypes REPLACES the one Expo generates
                // from the top-level `scheme` — it does not merge. Without
                // the app scheme listed here, privasys-wallet:// has NO
                // handler in the built app and every same-device handoff
                // (auth SDK 'Open in Privasys Wallet', the IdP /device
                // page) dies with Safari's "address is invalid". Regressed
                // 2026-04-17 when the Google entry was added.
                CFBundleURLTypes: [
                    { CFBundleURLSchemes: [config.scheme] },
                    // Google OAuth requires the reversed client ID as a
                    // registered URL scheme so iOS can route the redirect
                    // back to the app after authentication.
                    ...(process.env.EXPO_PUBLIC_OAUTH_GOOGLE_CLIENT_ID_IOS
                        ? [{
                            CFBundleURLSchemes: [
                                `com.googleusercontent.apps.${process.env.EXPO_PUBLIC_OAUTH_GOOGLE_CLIENT_ID_IOS.replace('.apps.googleusercontent.com', '')}`
                            ]
                        }]
                        : [])
                ]
            },
            config: { usesNonExemptEncryption: false },
            associatedDomains: ['applinks:privasys.id', 'webcredentials:privasys.id'],
            // NFC tag reading for the eMRTD (passport/ID chip) KYC flow. Requires
            // the matching capability enabled on the org.privasys.wallet App ID.
            entitlements: {
                'com.apple.developer.nfc.readersession.formats': ['TAG'],
                // This target declared none before, relying on the implicit
                // default group `<prefix>.<bundle id>` — the exact string the
                // transfer changed. Naming both prefixes explicitly is what
                // keeps an existing wallet readable after the update.
                'keychain-access-groups': [
                    '$(AppIdentifierPrefix)org.privasys.wallet',
                    ...SHARED_KEYCHAIN_GROUPS,
                    ...legacyGroup('org.privasys.wallet'),
                ]
            }
        },
        android: {
            // Submission to Google Play requires a unique package name.
            package: config.bundle,
            adaptiveIcon: {
                foregroundImage: config.icon,
                backgroundColor: config.adaptiveIconBackgroundColor
            },
            // predictiveBackGestureEnabled: true
            googleServicesFile: './fixtures/org.privasys.wallet.google-services.json',
            intentFilters: [
                {
                    action: 'VIEW',
                    autoVerify: true,
                    data: [{ scheme: 'https', host: '*.privasys.id', pathPrefix: '/scp' }],
                    category: ['BROWSABLE', 'DEFAULT']
                }
            ]
        },
        web: { favicon: config.icon, output: 'static', bundler: 'metro' },
        extra: {
            STAGE,
            CODE_VERSION: version,
            BUILD_ID: process.env.EAS_BUILD_ID ?? '-',
            BUILD_NUMBER:
                process.env.EAS_BUILD_IOS_BUILD_NUMBER ??
                process.env.EAS_BUILD_ANDROID_VERSION_CODE ??
                '0',
            COMMIT_HASH: getCommitHash(),
            eas: {
                projectId: EXPO_PROJECT_ID,
                build: {
                    experimental: {
                        ios: {
                            appExtensions: [
                                {
                                    targetName: 'NotificationServiceExtension',
                                    bundleIdentifier: `${config.bundle}.NotificationService`,
                                    entitlements: {
                                        'keychain-access-groups': SHARED_KEYCHAIN_GROUPS
                                    }
                                },
                                {
                                    targetName: 'PasskeyProvider',
                                    bundleIdentifier: `${config.bundle}.PasskeyProvider`,
                                    entitlements: {
                                        'com.apple.developer.authentication-services.autofill-credential-provider': true,
                                        'keychain-access-groups': SHARED_KEYCHAIN_GROUPS,
                                        'com.apple.developer.associated-domains': [
                                            'webcredentials:privasys.id'
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        },
        plugins: [
            [
                'expo-secure-store',
                {
                    configureAndroidBackup: true,
                    faceIDPermission:
                        '$(PRODUCT_NAME) uses your biometrics to validate your connection requests.'
                }
            ],
            [
                'expo-build-properties',
                {
                    android: {
                        compileSdkVersion: 36,
                        targetSdkVersion: 36,
                        buildToolsVersion: '36.1.0',
                        kotlinVersion: '2.1.20',
                        // R8. Play Console flags an unoptimised release build,
                        // and this is the flag it is asking about:
                        // developer.android.com/topic/performance/app-optimization/enable-app-optimization
                        //
                        // `shrinkResources` is deliberately NOT enabled with it.
                        // That is a separate, more aggressive pass over
                        // resources for a much smaller saving, and it strips
                        // anything referenced only by name. Clear the Play
                        // warning first, then consider it on its own.
                        enableMinifyInReleaseBuilds: true,
                        // Everything R8 cannot see. Each of these fails at
                        // RUNTIME, not at build time, so a green CI build says
                        // nothing about whether they are right.
                        extraProguardRules: [
                            '# --- JNI bridge to the Rust RA-TLS client ---',
                            '# The native symbol is the mangled CLASS + METHOD name, so renaming',
                            '# either gives an UnsatisfiedLinkError on the first attestation, which',
                            '# is every single sign-in. The bundled proguard-android.txt already',
                            '# keeps classes with native methods; this states it outright rather',
                            '# than depending on a file we do not own staying that way.',
                            '-keep class org.privasys.nativeratls.NativeRaTlsBridge { *; }',
                            '-keepclasseswithmembernames class * { native <methods>; }',
                            '',
                            '# --- Passport and eID reading ---',
                            '# JMRTD and SCUBA resolve card services and codecs by name, and',
                            '# BouncyCastle registers its algorithms reflectively through the JCA',
                            '# provider. R8 sees no reference to any of it and strips it, and the',
                            '# failure only appears when someone holds a real document to a real',
                            '# phone, which no build can reproduce.',
                            '-keep class org.jmrtd.** { *; }',
                            '-keep class net.sf.scuba.** { *; }',
                            '-keep class org.bouncycastle.** { *; }',
                            '-dontwarn org.jmrtd.**',
                            '-dontwarn net.sf.scuba.**',
                            '-dontwarn org.bouncycastle.**',
                            '-dontwarn javax.naming.**'
                        ].join('\n')
                    },
                    ios: { deploymentTarget: '16.0' }
                }
            ],
            [
                'expo-camera',
                {
                    cameraPermission: '$(PRODUCT_NAME) needs your camera to scan login QR codes.',
                    recordAudioAndroid: false
                }
            ],
            ['expo-router', { root: './src/routes' }],
            ['expo-navigation-bar', { barStyle: 'dark-content', visibility: 'visible' }],
            'expo-localization',
            // sentryUrl
            //     ? [
            //         '@sentry/react-native/expo',
            //         {
            //             url: sentryUrl.origin,
            //             project: 'privasys-wallet',
            //             organization: 'privasys'
            //         }
            //     ]
            //     : 'noop',
            'expo-asset',
            'expo-font',
            'expo-image',
            'expo-web-browser',
            ['expo-notifications', { icon: './assets/notification-icon.png', color: '#B21D36' }],
            './modules/passkey-provider/app.plugin',
            './modules/notification-service/app.plugin',
            './modules/app-attest/app.plugin',
            './plugins/swift-concurrency-fix',
            './plugins/disable-lint-vital'
        ].filter((p) => p !== 'noop') as ExpoConfig['plugins'],
        experiments: { typedRoutes: true, reactCompiler: true, buildCacheProvider: 'eas' }
    };

    return finalConfig;
};
