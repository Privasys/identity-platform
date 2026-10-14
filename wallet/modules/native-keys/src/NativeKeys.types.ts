// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

export interface KeyInfo {
    /** Opaque key identifier (tag on iOS, alias on Android). */
    keyId: string;
    /** Base64url-encoded uncompressed P-256 public key (65 bytes: 0x04 || x || y). */
    publicKey: string;
    /** Whether the key is backed by secure hardware (SE/StrongBox/TEE). */
    hardwareBacked: boolean;
    /**
     * How the key gates its use: `biometric` (bound to the enrolment that
     * existed at creation), `passcode` (the phone had no usable biometric, so
     * the device passcode unlocks it) or `none`. iOS reports it; Android keys
     * accept a strong biometric or the device credential and omit it.
     */
    protection?: 'biometric' | 'passcode' | 'none';
}

export interface SignatureResult {
    /** Base64url-encoded DER ECDSA signature. */
    signature: string;
}
