// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// expo-local-authentication is a native module shipped as ES modules, which
// Jest cannot load. Tests run without a biometric sensor, so this stands in:
// a prompt always succeeds and no sensor type is reported.
module.exports = {
    AuthenticationType: { FINGERPRINT: 1, FACIAL_RECOGNITION: 2, IRIS: 3 },
    hasHardwareAsync: async () => true,
    isEnrolledAsync: async () => true,
    supportedAuthenticationTypesAsync: async () => [],
    authenticateAsync: async () => ({ success: true }),
};
