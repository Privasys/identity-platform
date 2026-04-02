// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Connect flow — the core authentication journey:
 * 1. Parse QR payload (origin, sessionId, rpId, brokerUrl)
 * 2. RA-TLS attestation verification
 * 3. FIDO2 registration or authentication
 * 4. Relay session token to browser via broker
 */

import * as LocalAuthentication from 'expo-local-authentication';
import { useRouter, useLocalSearchParams, Stack } from 'expo-router';
import { useState, useEffect, useCallback, useRef } from 'react';
import { StyleSheet, Pressable, ActivityIndicator, ScrollView } from 'react-native';

import { Text, View } from '@/components/Themed';
import { useExpoPushToken } from '@/hooks/useExpoPushToken';
import { inspectAttestation } from '@/services/attestation';
import { relaySessionToken } from '@/services/broker';
import * as fido2 from '@/services/fido2';
import { useAuthStore } from '@/stores/auth';
import { useSettingsStore } from '@/stores/settings';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';

type FlowStep =
    | 'verifying'
    | 'attestation'
    | 'attestation-changed'
    | 'biometric'
    | 'authenticating'
    | 'relaying'
    | 'done'
    | 'error';

interface QRPayload {
    origin: string;
    sessionId: string;
    rpId: string;
    brokerUrl: string;
}

export default function ConnectScreen() {
    const router = useRouter();
    const params = useLocalSearchParams<{
        payload?: string; // JSON-encoded QRPayload
        serviceUrl?: string; // Legacy fallback
    }>();
    const pushToken = useExpoPushToken();

    // Stores
    const { addCredential, getCredentialForRp, checkUnlocked, setUnlocked } = useAuthStore();
    const { getApp, isAttestationMatch, addOrUpdate: addTrustedApp } = useTrustedAppsStore();
    const { gracePeriodSec } = useSettingsStore();

    // State
    const [step, setStep] = useState<FlowStep>('verifying');
    const [error, setError] = useState<string | null>(null);
    const [attestation, setAttestation] = useState<AttestationResult | null>(null);
    const [qr, setQr] = useState<QRPayload | null>(null);
    const [isTrusted, setIsTrusted] = useState(false);
    const hasStarted = useRef(false);

    // Parse QR payload
    useEffect(() => {
        if (hasStarted.current) return;
        hasStarted.current = true;

        let parsed: QRPayload;
        try {
            if (params.payload) {
                parsed = JSON.parse(params.payload);
            } else if (params.serviceUrl) {
                // Legacy QR format
                const url = new URL(params.serviceUrl);
                parsed = {
                    origin: url.host,
                    sessionId: url.pathname.split('/').pop() || '',
                    rpId: url.hostname,
                    brokerUrl: `wss://${url.host}/relay`
                };
            } else {
                setError('No connection payload received');
                setStep('error');
                return;
            }
        } catch {
            setError('Invalid QR code payload');
            setStep('error');
            return;
        }

        console.log('[CONNECT] QR parsed:', JSON.stringify(parsed));
        setQr(parsed);
        startFlow(parsed);
    }, []);

    const startFlow = useCallback(
        async (payload: QRPayload) => {
            setStep('verifying');
            console.log(`[CONNECT] startFlow — inspecting attestation for ${payload.origin}`);
            try {
                const result = await inspectAttestation(payload.origin);
                console.log(`[CONNECT] attestation OK — mrenclave=${result.mrenclave?.substring(0, 16)}...`);
                setAttestation(result);

                // Check if this is a trusted app with matching attestation
                const trustedApp = getApp(payload.rpId);
                if (
                    trustedApp &&
                    isAttestationMatch(payload.rpId, {
                        mrenclave: result.mrenclave,
                        mrtd: result.mrtd,
                        codeHash: result.code_hash,
                        configRoot: result.config_merkle_root
                    })
                ) {
                    setIsTrusted(true);
                    const credential = getCredentialForRp(payload.rpId);
                    if (credential && checkUnlocked()) {
                        // Within grace period — authenticate silently
                        await doAuthenticate(payload, credential.keyAlias, credential.credentialId);
                        return;
                    }
                    setStep('biometric');
                    return;
                }

                if (trustedApp) {
                    setStep('attestation-changed');
                    return;
                }

                // New app — show full attestation details
                setStep('attestation');
            } catch (e: any) {
                console.error(`[CONNECT] attestation FAILED:`, e.message, e);
                setError(`Attestation verification failed: ${e.message}`);
                setStep('error');
            }
        },
        [getApp, isAttestationMatch, getCredentialForRp, checkUnlocked]
    );

    const handleApprove = useCallback(async () => {
        if (!qr || !attestation) return;
        setStep('biometric');

        const result = await LocalAuthentication.authenticateAsync({
            promptMessage: `Connect to ${qr.rpId}`,
            fallbackLabel: 'Use Passcode',
            cancelLabel: 'Cancel',
            disableDeviceFallback: false
        });

        if (!result.success) {
            setError('Authentication cancelled');
            setStep('error');
            return;
        }

        if (gracePeriodSec > 0) {
            setUnlocked(gracePeriodSec * 1000);
        }

        const credential = getCredentialForRp(qr.rpId);
        if (credential) {
            await doAuthenticate(qr, credential.keyAlias, credential.credentialId);
        } else {
            await doRegister(qr);
        }
    }, [qr, attestation, gracePeriodSec]);

    const doRegister = async (payload: QRPayload) => {
        setStep('authenticating');
        console.log(`[CONNECT] doRegister — origin=${payload.origin}, rpId=${payload.rpId}`);
        try {
            const keyAlias = `fido2-${payload.rpId}`;
            const result = await fido2.register(payload.origin, keyAlias, payload.sessionId);

            addCredential({
                credentialId: result.credentialId,
                rpId: payload.rpId,
                origin: payload.origin,
                keyAlias,
                userHandle: result.userHandle,
                userName: result.userName,
                registeredAt: Math.floor(Date.now() / 1000)
            });

            if (attestation) {
                addTrustedApp({
                    rpId: payload.rpId,
                    origin: payload.origin,
                    mrenclave: attestation.mrenclave,
                    mrtd: attestation.mrtd,
                    codeHash: attestation.code_hash,
                    configRoot: attestation.config_merkle_root,
                    teeType: attestation.tee_type || 'sgx',
                    lastVerified: Math.floor(Date.now() / 1000),
                    credentialId: result.credentialId
                });
            }

            setStep('relaying');
            await relaySessionToken(
                payload.brokerUrl,
                payload.sessionId,
                result.sessionToken,
                pushToken
            );

            setStep('done');
            setTimeout(() => router.replace('/(tabs)'), 1500);
        } catch (e: any) {
            console.error(`[CONNECT] registration FAILED:`, e.message, e);
            setError(`Registration failed: ${e.message}`);
            setStep('error');
        }
    };

    const doAuthenticate = async (
        payload: QRPayload,
        keyAlias: string,
        credentialId: string
    ) => {
        setStep('authenticating');
        console.log(`[CONNECT] doAuthenticate — origin=${payload.origin}, credentialId=${credentialId.substring(0, 16)}...`);
        try {
            const result = await fido2.authenticate(
                payload.origin,
                keyAlias,
                credentialId,
                payload.sessionId
            );

            setStep('relaying');
            await relaySessionToken(
                payload.brokerUrl,
                payload.sessionId,
                result.sessionToken,
                pushToken
            );

            setStep('done');
            setTimeout(() => router.replace('/(tabs)'), 1500);
        } catch (e: any) {
            console.error(`[CONNECT] authentication FAILED:`, e.message, e);
            setError(`Authentication failed: ${e.message}`);
            setStep('error');
        }
    };

    const handleReject = () => {
        router.replace('/(tabs)');
    };

    return (
        <>
            <Stack.Screen options={{ headerShown: false }} />
            <View style={styles.container}>
                {step === 'verifying' && (
                    <View style={styles.centered}>
                        <ActivityIndicator size="large" color="#007AFF" />
                        <Text style={styles.statusText}>Verifying enclave attestation...</Text>
                    </View>
                )}

                {step === 'attestation' && attestation && qr && (
                    <AttestationView
                        attestation={attestation}
                        rpId={qr.rpId}
                        isChanged={false}
                        onApprove={handleApprove}
                        onReject={handleReject}
                    />
                )}

                {step === 'attestation-changed' && attestation && qr && (
                    <AttestationView
                        attestation={attestation}
                        rpId={qr.rpId}
                        isChanged={true}
                        onApprove={handleApprove}
                        onReject={handleReject}
                    />
                )}

                {step === 'biometric' && (
                    <View style={styles.centered}>
                        <Text style={styles.title}>Authenticate</Text>
                        <Text style={styles.subtitle}>
                            {isTrusted
                                ? `Sign in to ${qr?.rpId}`
                                : 'Confirm with biometrics to continue'}
                        </Text>
                        <ActivityIndicator size="large" color="#007AFF" />
                    </View>
                )}

                {step === 'authenticating' && (
                    <View style={styles.centered}>
                        <ActivityIndicator size="large" color="#007AFF" />
                        <Text style={styles.statusText}>
                            {getCredentialForRp(qr?.rpId || '')
                                ? 'Signing in...'
                                : 'Registering credential...'}
                        </Text>
                    </View>
                )}

                {step === 'relaying' && (
                    <View style={styles.centered}>
                        <ActivityIndicator size="large" color="#007AFF" />
                        <Text style={styles.statusText}>Sending to browser...</Text>
                    </View>
                )}

                {step === 'done' && (
                    <View style={styles.centered}>
                        <Text style={styles.checkmark}>✓</Text>
                        <Text style={styles.title}>Connected</Text>
                        <Text style={styles.subtitle}>
                            You can now use the service in your browser.
                        </Text>
                    </View>
                )}

                {step === 'error' && (
                    <View style={styles.centered}>
                        <Text style={styles.errorIcon}>✕</Text>
                        <Text style={styles.title}>Connection Failed</Text>
                        {error && <Text style={styles.errorText}>{error}</Text>}
                        <Pressable style={styles.secondaryButton} onPress={handleReject}>
                            <Text style={styles.secondaryButtonText}>Go back</Text>
                        </Pressable>
                    </View>
                )}
            </View>
        </>
    );
}

// ── Attestation detail view ─────────────────────────────────────────────

function AttestationView({
    attestation,
    rpId,
    isChanged,
    onApprove,
    onReject
}: {
    attestation: AttestationResult;
    rpId: string;
    isChanged: boolean;
    onApprove: () => void;
    onReject: () => void;
}) {
    return (
        <ScrollView contentContainerStyle={styles.attestationContainer}>
            {isChanged && (
                <View style={styles.warningBanner}>
                    <Text style={styles.warningText}>
                        ⚠ This app's attestation has changed since you last verified it.
                    </Text>
                </View>
            )}

            <Text style={styles.title}>{isChanged ? 'App Changed' : 'Verify Enclave'}</Text>
            <Text style={styles.subtitle}>{rpId}</Text>

            <View style={styles.attestationCard}>
                <AttestationRow label="TEE Type" value={attestation.tee_type?.toUpperCase()} />
                <AttestationRow label="Valid" value={attestation.valid ? '✓ Yes' : '✕ No'} />
                {attestation.mrenclave && (
                    <AttestationRow
                        label="MRENCLAVE"
                        value={truncateHex(attestation.mrenclave)}
                    />
                )}
                {attestation.mrtd && (
                    <AttestationRow label="MRTD" value={truncateHex(attestation.mrtd)} />
                )}
                {attestation.code_hash && (
                    <AttestationRow
                        label="Code Hash"
                        value={truncateHex(attestation.code_hash)}
                    />
                )}
                {attestation.config_merkle_root && (
                    <AttestationRow
                        label="Config Root"
                        value={truncateHex(attestation.config_merkle_root)}
                    />
                )}
                {attestation.quote_verification_status && (
                    <AttestationRow
                        label="Quote Verification"
                        value={attestation.quote_verification_status}
                    />
                )}
                <AttestationRow label="Certificate" value={attestation.cert_subject} />
                <AttestationRow label="Valid From" value={attestation.cert_not_before} />
                <AttestationRow label="Valid Until" value={attestation.cert_not_after} />
            </View>

            <View style={styles.buttonRow}>
                <Pressable style={styles.rejectButton} onPress={onReject}>
                    <Text style={styles.rejectButtonText}>Reject</Text>
                </Pressable>
                <Pressable style={styles.approveButton} onPress={onApprove}>
                    <Text style={styles.approveButtonText}>
                        {isChanged ? 'Trust Anyway' : 'Approve'}
                    </Text>
                </Pressable>
            </View>
        </ScrollView>
    );
}

function AttestationRow({ label, value }: { label: string; value?: string }) {
    if (!value) return null;
    return (
        <View style={styles.attestationRow}>
            <Text style={styles.attestationLabel}>{label}</Text>
            <Text style={styles.attestationValue} selectable>
                {value}
            </Text>
        </View>
    );
}

function truncateHex(hex: string): string {
    if (hex.length <= 16) return hex;
    return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}

const styles = StyleSheet.create({
    container: { flex: 1 },
    centered: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        paddingHorizontal: 40
    },
    title: { fontSize: 24, fontWeight: 'bold', textAlign: 'center', marginBottom: 8 },
    subtitle: { fontSize: 16, textAlign: 'center', opacity: 0.7, marginBottom: 20 },
    statusText: { fontSize: 16, marginTop: 16, opacity: 0.7, textAlign: 'center' },
    checkmark: { fontSize: 64, color: '#34C759', marginBottom: 16 },
    errorIcon: { fontSize: 64, color: '#FF3B30', marginBottom: 16 },
    errorText: {
        fontSize: 14,
        color: '#FF3B30',
        textAlign: 'center',
        marginBottom: 20,
        paddingHorizontal: 20
    },
    attestationContainer: { padding: 20, paddingTop: 80 },
    warningBanner: {
        backgroundColor: '#FFF3CD',
        borderRadius: 8,
        padding: 12,
        marginBottom: 16
    },
    warningText: { color: '#856404', fontSize: 14, textAlign: 'center' },
    attestationCard: {
        backgroundColor: 'rgba(128,128,128,0.1)',
        borderRadius: 12,
        padding: 16,
        marginBottom: 24
    },
    attestationRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        paddingVertical: 8,
        borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: 'rgba(128,128,128,0.3)',
        backgroundColor: 'transparent'
    },
    attestationLabel: { fontSize: 13, opacity: 0.6, flex: 1 },
    attestationValue: { fontSize: 13, fontFamily: 'Inter', flex: 2, textAlign: 'right' },
    buttonRow: { flexDirection: 'row', justifyContent: 'space-between', gap: 12 },
    approveButton: {
        flex: 1,
        backgroundColor: '#34C759',
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center'
    },
    approveButtonText: { color: '#fff', fontSize: 17, fontWeight: '600' },
    rejectButton: {
        flex: 1,
        backgroundColor: 'rgba(128,128,128,0.2)',
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center'
    },
    rejectButtonText: { fontSize: 17, fontWeight: '600' },
    secondaryButton: {
        backgroundColor: '#007AFF',
        borderRadius: 12,
        paddingHorizontal: 32,
        paddingVertical: 14,
        minWidth: 160,
        alignItems: 'center'
    },
    secondaryButtonText: { color: '#fff', fontSize: 17, fontWeight: '600' }
});
