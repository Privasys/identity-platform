/**
 * How this phone verifies its holder, as the wallet attestation reports it.
 * Pure, with no native import, so it can be tested on its own.
 */
export type KeyProtection = 'biometric' | 'passcode';

/**
 * The protection behind the holder key: `biometric` when a biometric is
 * enrolled and the key was made under it, `passcode` when the phone has no
 * usable biometric (the key is then gated by the device passcode or PIN).
 * A key made without a biometric stays `passcode` even if one is enrolled
 * later: the passcode still unlocks it.
 */
export function keyProtectionFor(biometricEnrolled: boolean, keyInfoProtection?: string): KeyProtection {
    if (keyInfoProtection === 'passcode') return 'passcode';
    return biometricEnrolled ? 'biometric' : 'passcode';
}
