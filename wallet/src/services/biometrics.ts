// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Friendly, platform-appropriate names for the device's biometric unlock.
 *
 * Copy must never say "Face ID" to a fingerprint-only Android user (a real
 * report: an Android tester who only enrols a fingerprint was told to "Set up
 * Face ID"). We read the hardware's supported authenticators and pick a noun
 * that matches what the device actually offers, defaulting to a neutral term.
 */

import * as LocalAuthentication from 'expo-local-authentication';
import { Platform } from 'react-native';

/** The default label while the async capability probe is in flight, or if it
 *  fails. Neutral so it is never wrong on either platform. */
export const DEFAULT_BIOMETRIC_LABEL = Platform.OS === 'ios' ? 'Face ID' : 'biometric unlock';

/**
 * A short noun for the device's biometric unlock, e.g. "Face ID", "Touch ID",
 * "fingerprint", "fingerprint or face unlock". Reflects hardware capability
 * (not what is enrolled), which is enough to avoid platform-wrong wording.
 */
export async function biometricLabel(): Promise<string> {
    let types: LocalAuthentication.AuthenticationType[] = [];
    try {
        types = await LocalAuthentication.supportedAuthenticationTypesAsync();
    } catch {
        return DEFAULT_BIOMETRIC_LABEL;
    }
    const hasFace = types.includes(LocalAuthentication.AuthenticationType.FACIAL_RECOGNITION);
    const hasFinger = types.includes(LocalAuthentication.AuthenticationType.FINGERPRINT);

    if (Platform.OS === 'ios') {
        if (hasFace) return 'Face ID';
        if (hasFinger) return 'Touch ID';
        return 'biometrics';
    }
    // Android (and anything else): describe what the hardware offers.
    if (hasFinger && hasFace) return 'fingerprint or face unlock';
    if (hasFinger) return 'fingerprint';
    if (hasFace) return 'face unlock';
    return 'biometric unlock';
}

/** Capitalise a label for use at the start of a sentence or on a button
 *  ("fingerprint" → "Fingerprint"; "Face ID" stays "Face ID"). */
export function titleiseBiometric(label: string): string {
    return label.charAt(0).toUpperCase() + label.slice(1);
}
