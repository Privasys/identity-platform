// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * First-time onboarding flow.
 * Welcome → biometric check → hardware key generation → done.
 */

import { LinearGradient } from 'expo-linear-gradient';
import * as LocalAuthentication from 'expo-local-authentication';
import { useRouter, Stack } from 'expo-router';
import { useState } from 'react';
import { StyleSheet, Pressable, ActivityIndicator, View as RNView } from 'react-native';

import { Text, Image } from '@/components/Themed';
import { useAuthStore } from '@/stores/auth';

import * as NativeKeys from '../../modules/native-keys/src/index';

type Step = 'welcome' | 'biometric' | 'keygen' | 'done';

export default function OnboardingScreen() {
    const router = useRouter();
    const setOnboarded = useAuthStore((s) => s.setOnboarded);
    const [step, setStep] = useState<Step>('welcome');
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);

    const handleStart = async () => {
        setStep('biometric');
        setError(null);

        // Check biometric availability
        const hasHardware = await LocalAuthentication.hasHardwareAsync();
        if (!hasHardware) {
            setError('This device does not support biometric authentication.');
            return;
        }
        const isEnrolled = await LocalAuthentication.isEnrolledAsync();
        if (!isEnrolled) {
            setError('Please set up Face ID or fingerprint in your device settings first.');
            return;
        }

        // Verify biometrics work
        const result = await LocalAuthentication.authenticateAsync({
            promptMessage: 'Set up Privasys Wallet',
            fallbackLabel: 'Use Passcode',
            cancelLabel: 'Cancel',
            disableDeviceFallback: false
        });

        if (!result.success) {
            setError('Biometric authentication failed. Please try again.');
            setStep('welcome');
            return;
        }

        // Generate hardware key
        setStep('keygen');
        setLoading(true);
        try {
            const keyInfo = await NativeKeys.generateKey('privasys-wallet-default', true);
            if (!keyInfo.hardwareBacked) {
                console.warn('Key is not hardware-backed — device may lack Secure Enclave/StrongBox');
            }
            setStep('done');
        } catch (e: any) {
            setError(`Key generation failed: ${e.message}`);
            setStep('welcome');
        } finally {
            setLoading(false);
        }
    };

    const handleFinish = () => {
        setOnboarded();
        router.replace('/(tabs)');
    };

    return (
        <>
            <Stack.Screen options={{ headerShown: false }} />
            <LinearGradient
                colors={['#34E89E', '#00BCF2']}
                start={{ x: 0, y: 0 }}
                end={{ x: 1, y: 1 }}
                style={styles.gradient}
            >
                <RNView style={styles.container}>
                    <Image
                        style={styles.logo}
                        source={require('@/assets/images/privasys-logo.svg')}
                        contentFit="contain"
                        tintColor="#FFFFFF"
                        transition={500}
                    />

                    {step === 'welcome' && (
                        <>
                            <Text style={styles.title}>Welcome to Privasys Wallet</Text>
                            <Text style={styles.subtitle}>
                                Your identity, verified by hardware.{'\n'}
                                No passwords. No trust required.
                            </Text>
                            <Pressable
                                style={({ pressed }) => [
                                    styles.primaryButton,
                                    pressed && styles.primaryButtonPressed
                                ]}
                                onPress={handleStart}
                            >
                                <Text style={styles.primaryButtonText}>Create your identity</Text>
                            </Pressable>
                        </>
                    )}

                    {step === 'biometric' && (
                        <>
                            <Text style={styles.title}>Biometric Setup</Text>
                            <Text style={styles.subtitle}>
                                Authenticate to confirm your biometrics work correctly.
                            </Text>
                            <ActivityIndicator size="large" color="#FFFFFF" />
                        </>
                    )}

                    {step === 'keygen' && (
                        <>
                            <Text style={styles.title}>Creating Your Key</Text>
                            <Text style={styles.subtitle}>
                                Generating a hardware-backed signing key...{'\n'}
                                This key never leaves your device's secure hardware.
                            </Text>
                            {loading && <ActivityIndicator size="large" color="#FFFFFF" />}
                        </>
                    )}

                    {step === 'done' && (
                        <>
                            <Text style={styles.title}>You're all set!</Text>
                            <Text style={styles.subtitle}>
                                Your Privasys Wallet is ready.{'\n'}
                                Scan a QR code to connect to your first service.
                            </Text>
                            <Pressable
                                style={({ pressed }) => [
                                    styles.primaryButton,
                                    pressed && styles.primaryButtonPressed
                                ]}
                                onPress={handleFinish}
                            >
                                <Text style={styles.primaryButtonText}>Get started</Text>
                            </Pressable>
                        </>
                    )}

                    {error && <Text style={styles.error}>{error}</Text>}
                </RNView>
            </LinearGradient>
        </>
    );
}

const styles = StyleSheet.create({
    gradient: {
        flex: 1
    },
    container: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        paddingHorizontal: 40
    },
    logo: {
        width: 180,
        height: 44,
        marginBottom: 48,
        backgroundColor: 'transparent'
    },
    title: {
        fontSize: 28,
        fontWeight: '700',
        textAlign: 'center',
        marginBottom: 12,
        color: '#FFFFFF',
        letterSpacing: -0.5
    },
    subtitle: {
        fontSize: 17,
        textAlign: 'center',
        color: 'rgba(255, 255, 255, 0.85)',
        marginBottom: 40,
        lineHeight: 26
    },
    primaryButton: {
        backgroundColor: 'rgba(255, 255, 255, 0.2)',
        borderRadius: 16,
        borderWidth: 1.5,
        borderColor: 'rgba(255, 255, 255, 0.4)',
        paddingHorizontal: 36,
        paddingVertical: 16,
        minWidth: 220,
        alignItems: 'center'
    },
    primaryButtonPressed: {
        backgroundColor: 'rgba(255, 255, 255, 0.35)'
    },
    primaryButtonText: {
        color: '#FFFFFF',
        fontSize: 17,
        fontWeight: '600',
        letterSpacing: 0.3
    },
    error: {
        color: '#FFFFFF',
        backgroundColor: 'rgba(255, 59, 48, 0.3)',
        borderRadius: 12,
        paddingHorizontal: 20,
        paddingVertical: 12,
        marginTop: 24,
        textAlign: 'center',
        overflow: 'hidden'
    }
});
