import { keyProtectionFor } from '@/services/key-protection';

// What the wallet attestation says about how the holder key is protected.
describe('keyProtectionFor', () => {
    it('is biometric on iOS when a biometric is enrolled and the key was made under one', () => {
        expect(keyProtectionFor('ios', true, 'biometric')).toBe('biometric');
        expect(keyProtectionFor('ios', true, undefined)).toBe('biometric');
    });
    it('is passcode on iOS when the phone has no usable biometric', () => {
        expect(keyProtectionFor('ios', false, undefined)).toBe('passcode');
        expect(keyProtectionFor('ios', false, 'biometric')).toBe('passcode');
    });
    it('stays passcode on iOS for a key made without a biometric, even once one is enrolled', () => {
        expect(keyProtectionFor('ios', true, 'passcode')).toBe('passcode');
    });
    it('is always passcode on Android, where the device PIN also unlocks the key', () => {
        expect(keyProtectionFor('android', true, undefined)).toBe('passcode');
        expect(keyProtectionFor('android', true, 'biometric')).toBe('passcode');
        expect(keyProtectionFor('android', false, undefined)).toBe('passcode');
    });
});
