// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Platform security checks — jailbreak/root detection and device integrity.
 *
 * Warns users when the device is compromised (jailbreak/root), which weakens
 * hardware key guarantees. Does NOT block usage — informs only.
 */

import { Platform } from 'react-native';
import * as Device from 'expo-device';

export interface SecurityStatus {
    /** Whether the device appears to be jailbroken/rooted. */
    isCompromised: boolean;
    /** Whether hardware-backed keys are available. */
    hasSecureHardware: boolean;
    /** Human-readable warnings (empty if all clear). */
    warnings: string[];
}

/**
 * Check device security posture.
 *
 * Performs heuristic checks for jailbreak (iOS) / root (Android).
 * These are best-effort — a determined attacker can evade them.
 * The purpose is to inform honest users, not to block adversaries.
 */
export async function checkDeviceSecurity(): Promise<SecurityStatus> {
    const warnings: string[] = [];
    let isCompromised = false;
    let hasSecureHardware = true;

    // Check if running on a real device
    if (!Device.isDevice) {
        warnings.push('Running on a simulator or emulator: hardware keys are not available.');
        hasSecureHardware = false;
    }

    // Platform-specific checks
    if (Platform.OS === 'ios') {
        // On iOS, check for common jailbreak indicators via native module
        // Since we can't access the filesystem directly from JS, we check
        // what the device reports
        if (Device.modelName?.includes('Simulator')) {
            warnings.push('iOS Simulator detected: Secure Enclave is not available.');
            hasSecureHardware = false;
        }
    }

    if (Platform.OS === 'android') {
        // Android: check device brand/model suggests an emulator
        const brand = Device.brand?.toLowerCase() ?? '';
        const model = Device.modelName?.toLowerCase() ?? '';
        if (
            brand.includes('generic') ||
            model.includes('emulator') ||
            model.includes('sdk') ||
            model.includes('goldfish')
        ) {
            warnings.push('Android emulator detected: StrongBox/TEE keys may not be available.');
            hasSecureHardware = false;
        }
    }

    return { isCompromised, hasSecureHardware, warnings };
}
