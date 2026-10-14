import { keyProtectionFor } from '@/services/key-protection';

// What the wallet attestation says about how the holder key is protected.
describe('keyProtectionFor', () => {
    it('is biometric when a biometric is enrolled and the key was made under one', () => {
        expect(keyProtectionFor(true, 'biometric')).toBe('biometric');
        expect(keyProtectionFor(true, undefined)).toBe('biometric');
    });
    it('is passcode when the phone has no usable biometric', () => {
        expect(keyProtectionFor(false, undefined)).toBe('passcode');
        expect(keyProtectionFor(false, 'biometric')).toBe('passcode');
    });
    it('stays passcode for a key made without a biometric, even once one is enrolled', () => {
        expect(keyProtectionFor(true, 'passcode')).toBe('passcode');
    });
});
