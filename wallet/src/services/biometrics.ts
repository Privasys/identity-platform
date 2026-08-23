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

/**
 * The default label KEY while the async capability probe is in flight, or if
 * it fails. Neutral so it is never wrong on either platform.
 *
 * These are i18n keys rather than finished strings: the copy that embeds them
 * is translated, so the noun has to be too. "Face ID" and "Touch ID" are Apple
 * product names and stay untranslated in every locale, but "fingerprint" and
 * "face unlock" are ordinary nouns that must not stay English.
 */
export const DEFAULT_BIOMETRIC_LABEL_KEY =
    Platform.OS === 'ios' ? 'biometric.faceId' : 'biometric.default';

/**
 * The translation key for a short noun naming the device's biometric unlock.
 * Reflects hardware capability (not what is enrolled), which is enough to
 * avoid platform-wrong wording.
 */
export async function biometricLabelKey(): Promise<string> {
    let types: LocalAuthentication.AuthenticationType[] = [];
    try {
        types = await LocalAuthentication.supportedAuthenticationTypesAsync();
    } catch {
        return DEFAULT_BIOMETRIC_LABEL_KEY;
    }
    const hasFace = types.includes(LocalAuthentication.AuthenticationType.FACIAL_RECOGNITION);
    const hasFinger = types.includes(LocalAuthentication.AuthenticationType.FINGERPRINT);

    if (Platform.OS === 'ios') {
        if (hasFace) return 'biometric.faceId';
        if (hasFinger) return 'biometric.touchId';
        return 'biometric.biometrics';
    }
    // Android (and anything else): describe what the hardware offers.
    if (hasFinger && hasFace) return 'biometric.fingerprintOrFace';
    if (hasFinger) return 'biometric.fingerprint';
    if (hasFace) return 'biometric.faceUnlock';
    return 'biometric.default';
}

/**
 * Capitalise a TRANSLATED label for the start of a sentence or a button
 * ("fingerprint" to "Fingerprint"; "Face ID" stays "Face ID").
 *
 * Applied after translation, so it capitalises whatever the locale supplied.
 * `toUpperCase` is locale-invariant, which is what we want: no language in
 * the shipped set needs special casing rules for its first letter, and a
 * locale-aware fold would risk surprises for no benefit.
 */
export function titleiseBiometric(label: string): string {
    return label.charAt(0).toUpperCase() + label.slice(1);
}
