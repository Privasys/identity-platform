// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// The wallet on the UIKit scene life cycle.
//
// An app built with the iOS 27 SDK (Xcode 27) must use scenes: iOS 27 ends one
// that does not as it launches, before any of its code runs. Expo generates a
// scene delegate from SDK 58 and offers one in SDK 57 (expo-build-properties
// `ios.enableSceneSupport`); this SDK has neither, so this plugin does what
// that option does:
//
//   1. adds ./ios-scene-lifecycle/SceneDelegate.swift to the app target;
//   2. names it in Info.plist (UIApplicationSceneManifest);
//   3. takes the window and the start of React Native out of the app delegate,
//      since the scene delegate now does both.
//
// It refuses an app delegate it does not recognise, so a template that changes
// fails the prebuild and never ships an app with no window. Remove the plugin
// when the wallet moves to an SDK that has scenes of its own.

const { withAppDelegate, withInfoPlist, withXcodeProject, IOSConfig } = require('expo/config-plugins');
const fs = require('fs');
const path = require('path');

const SOURCE = path.join(__dirname, 'ios-scene-lifecycle', 'SceneDelegate.swift');
const FILE_NAME = 'SceneDelegate.swift';

const SCENE_MANIFEST = {
    UIApplicationSupportsMultipleScenes: false,
    UISceneConfigurations: {
        UIWindowSceneSessionRoleApplication: [
            {
                UISceneConfigurationName: 'Default Configuration',
                // The Objective-C name SceneDelegate.swift declares.
                UISceneDelegateClassName: 'WalletSceneDelegate',
            },
        ],
    },
};

const WINDOW_STATEMENT = /^[ \t]*window = UIWindow\(frame: UIScreen\.main\.bounds\)\r?\n/m;
const START_STATEMENT = /^[ \t]*factory\.startReactNative\([^)]*\)\r?\n/m;
const EMPTY_OS_WRAPPER = /^[ \t]*#if os\(iOS\) \|\| os\(tvOS\)\r?\n[ \t]*#endif\r?\n/m;
// What SceneDelegate.swift reads from the app delegate.
const REQUIRED = ['class AppDelegate: ExpoAppDelegate', 'var window: UIWindow?', 'var reactNativeFactory: RCTReactNativeFactory?'];

/** The app delegate without its window and without starting React Native. */
function updateAppDelegate(contents) {
    const done = !WINDOW_STATEMENT.test(contents) && !START_STATEMENT.test(contents);
    if (
        REQUIRED.some((text) => !contents.includes(text)) ||
        (!done && !(WINDOW_STATEMENT.test(contents) && START_STATEMENT.test(contents)))
    ) {
        throw new Error('[ios-scene-lifecycle] AppDelegate.swift is not the Expo app delegate this plugin knows');
    }
    return contents.replace(WINDOW_STATEMENT, '').replace(START_STATEMENT, '').replace(EMPTY_OS_WRAPPER, '');
}

function withSceneLifecycle(config) {
    config = withAppDelegate(config, (mod) => {
        if (mod.modResults.language !== 'swift') {
            throw new Error('[ios-scene-lifecycle] the app delegate is not Swift');
        }
        mod.modResults.contents = updateAppDelegate(mod.modResults.contents);
        return mod;
    });

    config = withInfoPlist(config, (mod) => {
        const declared = mod.modResults.UIApplicationSceneManifest;
        if (declared !== undefined && JSON.stringify(declared) !== JSON.stringify(SCENE_MANIFEST)) {
            throw new Error('[ios-scene-lifecycle] Info.plist already declares another UIApplicationSceneManifest');
        }
        mod.modResults.UIApplicationSceneManifest = SCENE_MANIFEST;
        return mod;
    });

    return withXcodeProject(config, (mod) => {
        const { platformProjectRoot, projectName } = mod.modRequest;
        fs.copyFileSync(SOURCE, path.join(platformProjectRoot, projectName, FILE_NAME));
        const filepath = `${projectName}/${FILE_NAME}`;
        if (!mod.modResults.hasFile(filepath)) {
            mod.modResults = IOSConfig.XcodeUtils.addBuildSourceFileToGroup({
                filepath,
                groupName: projectName,
                project: mod.modResults,
            });
        }
        return mod;
    });
}

module.exports = withSceneLifecycle;
module.exports.updateAppDelegate = updateAppDelegate;
module.exports.SCENE_MANIFEST = SCENE_MANIFEST;
