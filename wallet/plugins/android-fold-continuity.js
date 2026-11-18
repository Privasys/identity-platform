// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// A foldable that opens or closes changes the screen's smallest width.
// React Native's main activity does not declare that it handles the change,
// so Android would recreate it and the screen would lose its state (a form
// half answered, a folder half browsed). Declaring smallestScreenSize lets
// React Native relayout in place, as it already does for size and
// orientation.
const { withAndroidManifest } = require('@expo/config-plugins');

const NEEDED = ['screenSize', 'smallestScreenSize', 'screenLayout', 'orientation'];

module.exports = function withFoldContinuity(config) {
    return withAndroidManifest(config, (config) => {
        const app = config.modResults.manifest.application?.[0];
        const main = app?.activity?.find((a) => a.$['android:name'] === '.MainActivity');
        if (!main) throw new Error('[android-fold-continuity] MainActivity not found');
        const have = (main.$['android:configChanges'] ?? '').split('|').filter(Boolean);
        main.$['android:configChanges'] = [...new Set([...have, ...NEEDED])].join('|');
        return config;
    });
};
