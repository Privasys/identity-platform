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
process.env.EXPO_PUBLIC_GOOGLE_PROJECT_ID ??= process.env.GOOGLE_PROJECT_ID;
process.env.EXPO_PUBLIC_CHALLENGE_SECRET_KEY ??= process.env.CHALLENGE_SECRET_KEY;

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
                // Google OAuth requires the reversed client ID as a registered URL scheme
                // so iOS can route the redirect back to the app after authentication.
                CFBundleURLTypes: [
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
                'com.apple.developer.nfc.readersession.formats': ['TAG']
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
                                        'keychain-access-groups': [
                                            '$(AppIdentifierPrefix)org.privasys.shared'
                                        ]
                                    }
                                },
                                {
                                    targetName: 'PasskeyProvider',
                                    bundleIdentifier: `${config.bundle}.PasskeyProvider`,
                                    entitlements: {
                                        'com.apple.developer.authentication-services.autofill-credential-provider': true,
                                        'keychain-access-groups': [
                                            '$(AppIdentifierPrefix)org.privasys.shared'
                                        ],
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
                        kotlinVersion: '2.1.20'
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
