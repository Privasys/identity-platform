// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * First-time onboarding flow.
 * Welcome → biometric check → hardware key generation → profile setup → done.
 */

import { Ionicons } from '@expo/vector-icons';
import { LinearGradient } from 'expo-linear-gradient';
import * as LocalAuthentication from 'expo-local-authentication';
import { useRouter, Stack } from 'expo-router';
import { useState } from 'react';
import { StyleSheet, Pressable, ActivityIndicator, View as RNView, TextInput, ScrollView } from 'react-native';

import { Text, Image } from '@/components/Themed';
import { generateDid, generatePairwiseSeed, generateCanonicalDid } from '@/services/did';
import { getClientId, linkIdentityProvider, PROVIDERS, type ProviderConfig } from '@/services/identity';
import { recoverAccount } from '@/services/recovery';
import { useAuthStore } from '@/stores/auth';
import { useProfileStore, type LinkedProvider, type ProfileAttribute } from '@/stores/profile';

import * as NativeKeys from '../../modules/native-keys/src/index';

type Step = 'welcome' | 'biometric' | 'keygen' | 'profile' | 'recover' | 'done';

/** Provider button config for the UI. */
const PROVIDER_BUTTONS = [
    { key: 'github', icon: 'logo-github' as const, label: 'GitHub', color: '#24292F' },
    { key: 'google', icon: 'logo-google' as const, label: 'Google', color: '#4285F4' },
    { key: 'microsoft', icon: 'logo-microsoft' as const, label: 'Microsoft', color: '#00A4EF' },
    { key: 'linkedin', icon: 'logo-linkedin' as const, label: 'LinkedIn', color: '#0A66C2' }
];

export default function OnboardingScreen() {
    const router = useRouter();
    const setOnboarded = useAuthStore((s) => s.setOnboarded);
    const createProfile = useProfileStore((s) => s.createProfile);
    const [step, setStep] = useState<Step>('welcome');
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);

    // Profile fields
    const [displayName, setDisplayName] = useState('');
    const [email, setEmail] = useState('');
    const [avatarUri, setAvatarUri] = useState('');
    const [linkedProviders, setLinkedProviders] = useState<LinkedProvider[]>([]);
    const [seedAttributes, setSeedAttributes] = useState<ProfileAttribute[]>([]);
    const [linkingProvider, setLinkingProvider] = useState<string | null>(null);
    const [recoveringProvider, setRecoveringProvider] = useState<string | null>(null);

    const handleStart = async () => {
        setStep('biometric');
        setError(null);

        // Check biometric availability
        const hasHardware = await LocalAuthentication.hasHardwareAsync();
        if (!hasHardware) {
            setError('This device does not support biometric authentication.');
            setStep('welcome');
            return;
        }
        const isEnrolled = await LocalAuthentication.isEnrolledAsync();
        if (!isEnrolled) {
            setError('Please set up Face ID or fingerprint in your device settings first.');
            setStep('welcome');
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
            setStep('profile');
        } catch (e: any) {
            setError(`Key generation failed: ${e.message}`);
            setStep('welcome');
        } finally {
            setLoading(false);
        }
    };

    const handleLinkProvider = async (providerKey: string) => {
        setLinkingProvider(providerKey);
        setError(null);
        try {
            const providerTemplate = PROVIDERS[providerKey];
            if (!providerTemplate) throw new Error(`Unknown provider: ${providerKey}`);

            // Client IDs should be configured per environment
            const clientId = getClientId(providerKey);
            if (!clientId) {
                throw new Error(`No client ID configured for ${providerTemplate.displayName}.`);
            }

            const config: ProviderConfig = { ...providerTemplate, clientId };
            const result = await linkIdentityProvider(config);

            // Update linked providers
            setLinkedProviders((prev) => {
                const existing = prev.findIndex((p) => p.provider === providerKey);
                if (existing >= 0) {
                    const updated = [...prev];
                    updated[existing] = result.provider;
                    return updated;
                }
                return [...prev, result.provider];
            });

            // Seed profile fields from provider (first provider wins for each field)
            if (result.userInfo.name && !displayName) {
                setDisplayName(result.userInfo.name);
            }
            if (result.userInfo.email && !email) {
                setEmail(result.userInfo.email);
            }
            if (result.userInfo.picture && !avatarUri) {
                setAvatarUri(result.userInfo.picture);
            }

            // Accumulate seed attributes
            setSeedAttributes((prev) => {
                const newAttrs = [...prev];
                for (const attr of result.seedAttributes) {
                    const existing = newAttrs.findIndex((a) => a.key === attr.key);
                    if (existing < 0) {
                        newAttrs.push(attr);
                    }
                }
                return newAttrs;
            });
        } catch (e: any) {
            if (e.message !== 'Authentication cancelled') {
                setError(e.message);
            }
        } finally {
            setLinkingProvider(null);
        }
    };

    const handleFinishProfile = async () => {
        setLoading(true);
        setError(null);
        try {
            // Generate DID from hardware key (device-level)
            const did = await generateDid();

            // Generate pairwise seed for per-app derived identifiers
            const pairwiseSeed = await generatePairwiseSeed();

            // Generate canonical cross-device DID
            const canonicalDid = await generateCanonicalDid(pairwiseSeed);

            // Create profile
            createProfile({
                displayName: displayName || 'Privasys User',
                email,
                avatarUri,
                locale: '',
                did,
                canonicalDid,
                pairwiseSeed,
                linkedProviders,
                attributes: seedAttributes
            });

            setStep('done');
        } catch (e: any) {
            setError(`Profile creation failed: ${e.message}`);
        } finally {
            setLoading(false);
        }
    };

    const handleFinish = () => {
        setOnboarded();
        router.replace('/(tabs)');
    };

    const handleRecover = async (providerKey: string) => {
        setRecoveringProvider(providerKey);
        setError(null);
        setLoading(true);
        try {
            const clientId = getClientId(providerKey);
            if (!clientId) {
                throw new Error(`No client ID configured for ${providerKey}.`);
            }
            await recoverAccount(providerKey, clientId);
            setStep('done');
        } catch (e: any) {
            if (e.message !== 'Authentication cancelled') {
                setError(e.message);
            }
        } finally {
            setRecoveringProvider(null);
            setLoading(false);
        }
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
                            <Pressable
                                style={styles.skipButton}
                                onPress={() => setStep('recover')}
                            >
                                <Text style={styles.skipButtonText}>Recover existing account</Text>
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

                    {step === 'profile' && (
                        <ScrollView
                            style={styles.profileScroll}
                            contentContainerStyle={styles.profileContent}
                            showsVerticalScrollIndicator={false}
                            keyboardShouldPersistTaps="handled"
                        >
                            <Text style={styles.title}>Set Up Your Profile</Text>
                            <Text style={styles.subtitle}>
                                Link an account to populate your profile,{'\n'}
                                or enter your details manually.
                            </Text>

                            {/* Provider linking buttons */}
                            <RNView style={styles.providerGrid}>
                                {PROVIDER_BUTTONS.map((p) => {
                                    const isLinked = linkedProviders.some(
                                        (lp) => lp.provider === p.key
                                    );
                                    const isLinking = linkingProvider === p.key;
                                    return (
                                        <Pressable
                                            key={p.key}
                                            style={[
                                                styles.providerButton,
                                                isLinked && styles.providerButtonLinked
                                            ]}
                                            onPress={() => !isLinked && handleLinkProvider(p.key)}
                                            disabled={isLinking}
                                        >
                                            {isLinking ? (
                                                <ActivityIndicator size="small" color="#FFFFFF" />
                                            ) : (
                                                <Ionicons
                                                    name={p.icon}
                                                    size={20}
                                                    color="#FFFFFF"
                                                />
                                            )}
                                            <Text style={styles.providerButtonText}>
                                                {isLinked ? `${p.label} ✓` : p.label}
                                            </Text>
                                        </Pressable>
                                    );
                                })}
                            </RNView>

                            {/* Manual profile fields */}
                            <RNView style={styles.formGroup}>
                                <Text style={styles.inputLabel}>Display Name</Text>
                                <TextInput
                                    style={styles.textInput}
                                    value={displayName}
                                    onChangeText={setDisplayName}
                                    placeholder="Your name"
                                    placeholderTextColor="rgba(255,255,255,0.4)"
                                    autoCapitalize="words"
                                    autoCorrect={false}
                                />

                                <Text style={styles.inputLabel}>Email</Text>
                                <TextInput
                                    style={styles.textInput}
                                    value={email}
                                    onChangeText={setEmail}
                                    placeholder="your@email.com"
                                    placeholderTextColor="rgba(255,255,255,0.4)"
                                    autoCapitalize="none"
                                    keyboardType="email-address"
                                    autoCorrect={false}
                                />
                            </RNView>

                            <Pressable
                                style={({ pressed }) => [
                                    styles.primaryButton,
                                    pressed && styles.primaryButtonPressed,
                                    { marginTop: 24 }
                                ]}
                                onPress={handleFinishProfile}
                                disabled={loading}
                            >
                                {loading ? (
                                    <ActivityIndicator size="small" color="#FFFFFF" />
                                ) : (
                                    <Text style={styles.primaryButtonText}>Continue</Text>
                                )}
                            </Pressable>

                            <Pressable
                                style={styles.skipButton}
                                onPress={handleFinishProfile}
                            >
                                <Text style={styles.skipButtonText}>Skip for now</Text>
                            </Pressable>
                        </ScrollView>
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

                    {step === 'recover' && (
                        <ScrollView
                            style={styles.profileScroll}
                            contentContainerStyle={styles.profileContent}
                            showsVerticalScrollIndicator={false}
                        >
                            <Text style={styles.title}>Recover Your Account</Text>
                            <Text style={styles.subtitle}>
                                Sign in with a provider you previously linked.{'\n'}
                                A new device key will be created.
                            </Text>

                            <RNView style={styles.providerGrid}>
                                {PROVIDER_BUTTONS.map((p) => {
                                    const isRecovering = recoveringProvider === p.key;
                                    return (
                                        <Pressable
                                            key={p.key}
                                            style={styles.providerButton}
                                            onPress={() => handleRecover(p.key)}
                                            disabled={loading}
                                        >
                                            {isRecovering ? (
                                                <ActivityIndicator size="small" color="#FFFFFF" />
                                            ) : (
                                                <Ionicons
                                                    name={p.icon}
                                                    size={20}
                                                    color="#FFFFFF"
                                                />
                                            )}
                                            <Text style={styles.providerButtonText}>{p.label}</Text>
                                        </Pressable>
                                    );
                                })}
                            </RNView>

                            <Text style={styles.recoveryNote}>
                                Recovery creates a new cryptographic key on this device.
                                You'll need to re-register with any previously connected services.
                            </Text>

                            <Pressable
                                style={styles.skipButton}
                                onPress={() => setStep('welcome')}
                            >
                                <Text style={styles.skipButtonText}>Back</Text>
                            </Pressable>
                        </ScrollView>
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
    },
    profileScroll: {
        flex: 1,
        width: '100%'
    },
    profileContent: {
        alignItems: 'center',
        paddingBottom: 40
    },
    providerGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        gap: 10,
        justifyContent: 'center',
        marginBottom: 24,
        width: '100%'
    },
    providerButton: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 8,
        backgroundColor: 'rgba(255, 255, 255, 0.15)',
        borderRadius: 12,
        borderWidth: 1,
        borderColor: 'rgba(255, 255, 255, 0.3)',
        paddingHorizontal: 16,
        paddingVertical: 12,
        minWidth: 140
    },
    providerButtonLinked: {
        backgroundColor: 'rgba(52, 232, 158, 0.3)',
        borderColor: 'rgba(52, 232, 158, 0.6)'
    },
    providerButtonText: {
        color: '#FFFFFF',
        fontSize: 15,
        fontWeight: '500'
    },
    formGroup: {
        width: '100%',
        gap: 4
    },
    inputLabel: {
        color: 'rgba(255, 255, 255, 0.8)',
        fontSize: 13,
        fontWeight: '600',
        marginTop: 12,
        marginBottom: 4,
        textTransform: 'uppercase',
        letterSpacing: 0.5
    },
    textInput: {
        backgroundColor: 'rgba(255, 255, 255, 0.15)',
        borderRadius: 12,
        borderWidth: 1,
        borderColor: 'rgba(255, 255, 255, 0.3)',
        paddingHorizontal: 16,
        paddingVertical: 14,
        fontSize: 16,
        color: '#FFFFFF'
    },
    skipButton: {
        marginTop: 16,
        paddingVertical: 12
    },
    skipButtonText: {
        color: 'rgba(255, 255, 255, 0.7)',
        fontSize: 15,
        fontWeight: '500'
    },
    recoveryNote: {
        color: 'rgba(255, 255, 255, 0.6)',
        fontSize: 13,
        textAlign: 'center',
        lineHeight: 20,
        marginBottom: 8,
        paddingHorizontal: 16
    }
});
