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
import { getAttestationServerToken } from '@/services/app-attest';
import { inspectAttestation, verifyAttestation } from '@/services/attestation';
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
            console.log(`[CONNECT] startFlow — verifying attestation for ${payload.origin}`);
            try {
                let result: AttestationResult;
                try {
                    // Obtain an AS token via App Attest, then verify through the attestation server
                    const asToken = await getAttestationServerToken();
                    console.log('[CONNECT] obtained AS token, calling verify()');
                    result = await verifyAttestation(payload.origin, {
                        tee: 'sgx',
                        attestation_server: 'https://as.privasys.org',
                        attestation_server_token: asToken,
                    });
                } catch (verifyErr: any) {
                    // Fallback to inspect-only (e.g. simulator, App Attest unavailable)
                    console.warn(`[CONNECT] verify() unavailable, falling back to inspect: ${verifyErr.message}`);
                    result = await inspectAttestation(payload.origin);
                }
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
                        await doAuthenticate(payload, credential.keyAlias, credential.credentialId, credential.enclaveRpId);
                        return;
                    }
                    if (credential) {
                        // Trusted + has credential but outside grace period — prompt biometric
                        setStep('biometric');
                        await promptBiometricAndAuthenticate(payload, credential.keyAlias, credential.credentialId, credential.enclaveRpId);
                        return;
                    }
                    setStep('attestation');
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

    const promptBiometricAndAuthenticate = useCallback(async (
        payload: QRPayload,
        keyAlias: string,
        credentialId: string,
        enclaveRpId?: string
    ) => {
        const result = await LocalAuthentication.authenticateAsync({
            promptMessage: `Connect to ${payload.rpId}`,
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

        await doAuthenticate(payload, keyAlias, credentialId, enclaveRpId);
    }, [gracePeriodSec]);

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
            await doAuthenticate(qr, credential.keyAlias, credential.credentialId, credential.enclaveRpId);
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

            // Relay to browser BEFORE persisting — if relay fails the
            // credential must not appear in "Connected Services".
            setStep('relaying');
            await relaySessionToken(
                payload.brokerUrl,
                payload.sessionId,
                result.sessionToken,
                pushToken
            );

            // Relay succeeded — now persist locally.
            addCredential({
                credentialId: result.credentialId,
                rpId: payload.rpId,
                origin: payload.origin,
                keyAlias,
                userHandle: result.userHandle,
                userName: result.userName,
                registeredAt: Math.floor(Date.now() / 1000),
                enclaveRpId: result.enclaveRpId,
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
        credentialId: string,
        enclaveRpId?: string
    ) => {
        setStep('authenticating');
        console.log(`[CONNECT] doAuthenticate — origin=${payload.origin}, credentialId=${credentialId.substring(0, 16)}...`);
        try {
            const result = await fido2.authenticate(
                payload.origin,
                keyAlias,
                credentialId,
                payload.sessionId,
                enclaveRpId
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
                        <Pressable style={styles.cancelButton} onPress={handleReject}>
                            <Text style={styles.cancelButtonText}>Cancel</Text>
                        </Pressable>
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
                        <Pressable style={styles.cancelButton} onPress={handleReject}>
                            <Text style={styles.cancelButtonText}>Cancel</Text>
                        </Pressable>
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
    const appType = attestation.tee_type === 'sgx' ? 'WASM Application' : 'Container Application';
    const teeColor = attestation.tee_type === 'sgx' ? '#34E89E' : '#00BCF2';

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

            {/* Verification Status */}
            <View
                style={[
                    styles.statusBanner,
                    attestation.valid ? styles.statusBannerValid : styles.statusBannerInvalid
                ]}
            >
                <Text style={styles.statusIcon}>{attestation.valid ? '✓' : '✕'}</Text>
                <View style={styles.statusInfo}>
                    <Text
                        style={[
                            styles.statusTitle,
                            attestation.valid
                                ? styles.statusTitleValid
                                : styles.statusTitleInvalid
                        ]}
                    >
                        {attestation.valid ? 'Attestation Valid' : 'Attestation Invalid'}
                    </Text>
                    <Text style={styles.statusDetail}>
                        {appType} · {attestation.tee_type?.toUpperCase()} enclave
                    </Text>
                </View>
                <View style={[styles.teeBadge, { backgroundColor: teeColor }]}>
                    <Text style={styles.teeBadgeText}>{attestation.tee_type?.toUpperCase()}</Text>
                </View>
            </View>

            {/* Verification Details */}
            {(attestation.quote_verification_status ||
                attestation.attestation_servers_hash ||
                attestation.dek_origin) && (
                <>
                    <Text style={styles.sectionHeader}>Verification</Text>
                    <View style={styles.attestationCard}>
                        {attestation.quote_verification_status && (
                            <AttestationRow
                                label="Quote Status"
                                value={attestation.quote_verification_status}
                            />
                        )}
                        {attestation.attestation_servers_hash && (
                            <AttestationRow
                                label="Attestation Server"
                                value={truncateHex(attestation.attestation_servers_hash)}
                            />
                        )}
                        {attestation.dek_origin && (
                            <AttestationRow label="DEK Origin" value={attestation.dek_origin} />
                        )}
                    </View>
                </>
            )}

            {/* Enclave Identity */}
            <Text style={styles.sectionHeader}>Enclave Identity</Text>
            <View style={styles.attestationCard}>
                {attestation.mrenclave && (
                    <AttestationRow
                        label="MRENCLAVE"
                        value={truncateHex(attestation.mrenclave)}
                    />
                )}
                {attestation.mrsigner && (
                    <AttestationRow
                        label="MRSIGNER"
                        value={truncateHex(attestation.mrsigner)}
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
            </View>

            {/* Certificate */}
            <Text style={styles.sectionHeader}>Certificate</Text>
            <View style={styles.attestationCard}>
                <AttestationRow label="Subject" value={attestation.cert_subject} />
                <AttestationRow label="Valid From" value={attestation.cert_not_before} />
                <AttestationRow label="Valid Until" value={attestation.cert_not_after} />
            </View>

            {/* Advisory IDs */}
            {attestation.advisory_ids && attestation.advisory_ids.length > 0 && (
                <>
                    <Text style={styles.sectionHeader}>Advisories</Text>
                    <View style={styles.attestationCard}>
                        {attestation.advisory_ids.map((id) => (
                            <AttestationRow key={id} label={id} value="Known advisory" />
                        ))}
                    </View>
                </>
            )}

            {/* Custom OIDs */}
            {attestation.custom_oids && attestation.custom_oids.length > 0 && (
                <>
                    <Text style={styles.sectionHeader}>Custom Extensions</Text>
                    <View style={styles.attestationCard}>
                        {attestation.custom_oids.map((oid) => (
                            <AttestationRow
                                key={oid.oid}
                                label={oid.label || oid.oid}
                                value={truncateHex(oid.value_hex)}
                            />
                        ))}
                    </View>
                </>
            )}

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
    attestationContainer: { padding: 20, paddingTop: 80, paddingBottom: 40 },
    warningBanner: {
        backgroundColor: '#FFF3CD',
        borderRadius: 8,
        padding: 12,
        marginBottom: 16
    },
    warningText: { color: '#856404', fontSize: 14, textAlign: 'center' },
    statusBanner: {
        flexDirection: 'row',
        alignItems: 'center',
        borderRadius: 12,
        padding: 16,
        marginBottom: 24,
        gap: 12
    },
    statusBannerValid: { backgroundColor: '#E8FFF0' },
    statusBannerInvalid: { backgroundColor: '#FFF1F0' },
    statusIcon: { fontSize: 28, fontWeight: '700' },
    statusInfo: { flex: 1, backgroundColor: 'transparent' },
    statusTitle: { fontSize: 16, fontWeight: '700' },
    statusTitleValid: { color: '#166534' },
    statusTitleInvalid: { color: '#991B1B' },
    statusDetail: { fontSize: 13, color: '#64748B', marginTop: 2 },
    teeBadge: {
        paddingHorizontal: 10,
        paddingVertical: 4,
        borderRadius: 6
    },
    teeBadgeText: { color: '#fff', fontSize: 12, fontWeight: '700', letterSpacing: 0.5 },
    sectionHeader: {
        fontSize: 13,
        fontWeight: '600',
        color: '#94A3B8',
        textTransform: 'uppercase',
        letterSpacing: 0.5,
        marginBottom: 8,
        marginTop: 4
    },
    attestationCard: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 16
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
    secondaryButtonText: { color: '#fff', fontSize: 17, fontWeight: '600' },
    cancelButton: {
        marginTop: 24,
        paddingVertical: 12,
        paddingHorizontal: 24
    },
    cancelButtonText: { fontSize: 16, color: '#8E8E93' }
});
