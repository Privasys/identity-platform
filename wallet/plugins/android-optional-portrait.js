// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// Google's code scanner (GmsBarcodeScanningDelegateActivity, brought in by
// expo-camera) is locked to portrait. From that lock Google Play infers that
// the app requires android.hardware.screen.portrait, and refuses to send a
// release for review because the requirement shuts out tablets, desktops and
// Android XR. The wallet follows whatever orientation it is given, so it says
// outright that the feature is optional.
const { withAndroidManifest } = require('@expo/config-plugins');

const FEATURE = 'android.hardware.screen.portrait';

module.exports = function withOptionalPortrait(config) {
    return withAndroidManifest(config, (config) => {
        const manifest = config.modResults.manifest;
        const features = (manifest['uses-feature'] ??= []);
        const declared = features.find((f) => f.$['android:name'] === FEATURE);
        if (declared) declared.$['android:required'] = 'false';
        else features.push({ $: { 'android:name': FEATURE, 'android:required': 'false' } });
        return config;
    });
};
