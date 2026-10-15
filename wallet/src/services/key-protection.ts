/**
 * How this phone verifies its holder, as the wallet attestation reports it.
 * Pure, with no native import, so it can be tested on its own.
 */
export type KeyProtection = 'biometric' | 'passcode';

/**
 * The protection behind the holder key: what is enough to unlock it.
 *
 * - Android: always `passcode`. The key accepts the device PIN, pattern or
 *   password as well as a biometric, so a biometric is not required. It
 *   becomes `biometric` only once Android keys are made biometric-only,
 *   which means a new key and a new enrolment.
 * - iOS: `biometric` when a biometric is enrolled and the key was made
 *   under it (such a key refuses the passcode); `passcode` when the phone
 *   has no usable biometric, and for a key made without one even if one is
 *   enrolled later, since the passcode still unlocks it.
 */
export function keyProtectionFor(
    os: string,
    biometricEnrolled: boolean,
    keyInfoProtection?: string
): KeyProtection {
    if (os === 'android') return 'passcode';
    if (keyInfoProtection === 'passcode') return 'passcode';
    return biometricEnrolled ? 'biometric' : 'passcode';
}
