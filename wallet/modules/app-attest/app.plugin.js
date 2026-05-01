// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.
//
// Expo config plugin that adds the iOS App Attest entitlement to the main
// app target. Without this entitlement the OS refuses
// `DCAppAttestService.attestKey` calls with `com.apple.devicecheck.error
// error 2` ("The operation couldn't be completed"), even on supported
// hardware — observed on TestFlight builds prior to wallet 1.2.18.
//
// Entitlement key: `com.apple.developer.devicecheck.appattest-environment`
// (this IS the App Attest entitlement; it lives under the `devicecheck`
// namespace because Apple ships App Attest's API inside the DeviceCheck
// framework. It is NOT the legacy DeviceCheck per-device-bit-pair API.)
//
// Value is `production` for App Store / TestFlight builds and
// `development` for local dev builds. STAGE is read from the environment
// to match `app.config.ts`.
//
// EAS-managed credentials will sync this entitlement to the App ID and
// re-issue the provisioning profile with the App Attest capability on the
// next build — no manual portal action required.

const { withEntitlementsPlist } = require('@expo/config-plugins');

function withAppAttestEntitlement(config) {
    return withEntitlementsPlist(config, (mod) => {
        const stage = process.env.STAGE || 'development';
        const env = stage === 'development' ? 'development' : 'production';
        mod.modResults['com.apple.developer.devicecheck.appattest-environment'] = env;
        return mod;
    });
}

module.exports = withAppAttestEntitlement;
