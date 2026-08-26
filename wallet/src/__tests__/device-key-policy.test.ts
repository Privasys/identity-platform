// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Nothing but a wipe may delete the device's signing key.
 *
 * The key is the root of the device DID and of every holder proof, so
 * destroying it is a decision for the person holding the phone, taken once and
 * deliberately through "Clear All Data". A signing failure is never evidence
 * enough, however confident it looks: an earlier version replaced the key
 * automatically when the hardware refused it, which meant a bug, a transient
 * fault, or an induced error could quietly destroy identity material nobody
 * agreed to lose.
 *
 * What the signing path may do is recognise a key the hardware has retired and
 * say what fixes it. A biometric-gated key dies when the phone's fingerprint or
 * face enrolment changes: still listed, its public key still readable, every
 * signature refused for ever (CryptoTokenKit error -3 on a tester's iPhone,
 * 2026-08-26). The remedy is a wipe, and the error names it.
 */

jest.mock('expo-crypto', () => ({
    getRandomBytes: jest.fn((n: number) => new Uint8Array(n)),
    getRandomBytesAsync: jest.fn(async (n: number) => new Uint8Array(n)),
    digestStringAsync: jest.fn(async () => '00'.repeat(32)),
}));

// Factories are declared inline: jest.mock is hoisted above every const in the
// file, so one that closes over a local runs while that binding is still in its
// temporal dead zone.
jest.mock('../../modules/native-keys/src/index', () => ({
    sign: jest.fn(),
    deleteKey: jest.fn(),
    generateKey: jest.fn(),
    getPublicKey: jest.fn(),
    keyExists: jest.fn(),
}));

import { DeviceKeyUnusableError, signWithDeviceKey } from '@/services/did';
import * as NativeKeys from '../../modules/native-keys/src/index';

const mockNativeKeys = NativeKeys as unknown as {
    sign: jest.Mock;
    deleteKey: jest.Mock;
    generateKey: jest.Mock;
    getPublicKey: jest.Mock;
    keyExists: jest.Mock;
};

beforeEach(() => {
    jest.clearAllMocks();
    mockNativeKeys.deleteKey.mockResolvedValue(undefined);
    mockNativeKeys.generateKey.mockResolvedValue({ publicKey: 'newpub', keyId: 'k' });
    mockNativeKeys.getPublicKey.mockResolvedValue({ publicKey: 'newpub', keyId: 'k' });
    mockNativeKeys.keyExists.mockResolvedValue(true);
});

describe('signWithDeviceKey', () => {
    it('returns the signature when the key works', async () => {
        mockNativeKeys.sign.mockResolvedValueOnce({ signature: 'sig-1' });
        await expect(signWithDeviceKey('ZGF0YQ')).resolves.toBe('sig-1');
    });

    // The reported failure, verbatim from the tester's log.
    it('reports a retired key as unusable, and names the remedy', async () => {
        mockNativeKeys.sign.mockRejectedValueOnce(
            new Error("NativeKeys.sign: The operation couldn't be completed. (CryptoTokenKit error -3.)"),
        );

        await expect(signWithDeviceKey('ZGF0YQ')).rejects.toBeInstanceOf(DeviceKeyUnusableError);
    });

    it('keeps the platform wording for the log without putting it in the message', async () => {
        const platformWording = "The operation couldn't be completed. (CryptoTokenKit error -3.)";
        mockNativeKeys.sign.mockRejectedValueOnce(new Error(platformWording));

        const err: DeviceKeyUnusableError = await signWithDeviceKey('ZGF0YQ').then(
            () => { throw new Error('expected a rejection'); },
            (e) => e as DeviceKeyUnusableError,
        );
        expect(err.platformMessage).toContain('CryptoTokenKit error -3');
        expect(err.message).toContain('Clear all data');
        expect(err.message).not.toContain('CryptoTokenKit');
    });

    it.each([
        ['a vanished key', 'NativeKeys.sign: key not found'],
        ['an Android enrolment change', 'android.security.keystore.KeyPermanentlyInvalidatedException'],
    ])('recognises %s', async (_label, message) => {
        mockNativeKeys.sign.mockRejectedValueOnce(new Error(message));
        await expect(signWithDeviceKey('ZGF0YQ')).rejects.toBeInstanceOf(DeviceKeyUnusableError);
    });

    // An ordinary refusal is passed through untouched. Dressing one of these up
    // as "your key is broken, wipe the wallet" would be its own kind of damage.
    it.each([
        ['the user cancelled', 'The operation couldn’t be completed. (CryptoTokenKit error -4.)'],
        ['the match failed', 'The operation couldn’t be completed. (CryptoTokenKit error -5.)'],
        ['authentication is needed', 'The operation couldn’t be completed. (CryptoTokenKit error -9.)'],
        ['Android wanted a fresh unlock', 'KeyStoreException: Key user not authenticated'],
        ['the user dismissed Face ID', 'User canceled the operation.'],
        ['something unexpected', 'Kernel panic in the disco biscuit factory'],
    ])('passes through %s unchanged', async (_label, message) => {
        mockNativeKeys.sign.mockRejectedValue(new Error(message));

        const err: Error = await signWithDeviceKey('ZGF0YQ').then(
            () => { throw new Error('expected a rejection'); },
            (e) => e as Error,
        );
        expect(err).not.toBeInstanceOf(DeviceKeyUnusableError);
        expect(err.message).toBe(message);
    });

    // The rule this file exists for.
    it.each([
        'NativeKeys.sign: The operation couldn’t be completed. (CryptoTokenKit error -3.)',
        'NativeKeys.sign: key not found',
        'KeyPermanentlyInvalidatedException',
        'The operation couldn’t be completed. (CryptoTokenKit error -4.)',
        'Kernel panic in the disco biscuit factory',
    ])('never deletes or regenerates the key: %s', async (message) => {
        mockNativeKeys.sign.mockRejectedValue(new Error(message));

        await signWithDeviceKey('ZGF0YQ').catch(() => undefined);

        expect(mockNativeKeys.deleteKey).not.toHaveBeenCalled();
        expect(mockNativeKeys.generateKey).not.toHaveBeenCalled();
        // One attempt. No silent retry that could mask a prompt the user saw.
        expect(mockNativeKeys.sign).toHaveBeenCalledTimes(1);
    });
});
