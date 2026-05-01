// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Batch Connect — authenticate with multiple enclaves in a single approval.
 *
 * 1. Parse batch QR payload (multiple apps)
 * 2. Verify attestation for each app (parallel)
 * 3. Single biometric prompt
 * 4. FIDO2 register/authenticate for each app
 * 5. Relay all session tokens to browser via broker
 */

import * as LocalAuthentication from 'expo-local-authentication';
import { useRouter, useLocalSearchParams, Stack } from 'expo-router';
import { useState, useEffect, useCallback, useRef } from 'react';
import { StyleSheet, Pressable, ActivityIndicator, ScrollView, FlatList } from 'react-native';

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

type BatchStep =
    | 'verifying'
    | 'review'
    | 'biometric'
    | 'authenticating'
    | 'relaying'
    | 'done'
    | 'error';

interface BatchQRPayload {
    origin: string;
    sessionId: string;
    brokerUrl: string;
    apps: Array<{ rpId: string; sessionId: string }>;
}

interface AppEntry {
    rpId: string;
    sessionId: string;
    attestation: AttestationResult | null;
    isTrusted: boolean;
    isChanged: boolean;
    status: 'pending' | 'verified' | 'failed' | 'authenticated' | 'relayed';
    error?: string;
}

export default function BatchConnectScreen() {
    const router = useRouter();
    const params = useLocalSearchParams<{ payload?: string }>();
    const pushToken = useExpoPushToken();

    const { addCredential, getCredentialForRp, checkUnlocked, setUnlocked } = useAuthStore();
    const { getApp, isAttestationMatch, addOrUpdate: addTrustedApp } = useTrustedAppsStore();
    const { gracePeriodSec } = useSettingsStore();

    const [step, setStep] = useState<BatchStep>('verifying');
    const [error, setError] = useState<string | null>(null);
    const [batch, setBatch] = useState<BatchQRPayload | null>(null);
    const [apps, setApps] = useState<AppEntry[]>([]);
    const hasStarted = useRef(false);

    useEffect(() => {
        if (hasStarted.current) return;
        hasStarted.current = true;

        if (!params.payload) {
            setError('No batch payload received');
            setStep('error');
            return;
        }

        let parsed: BatchQRPayload;
        try {
            parsed = JSON.parse(params.payload);
        } catch {
            setError('Invalid batch payload');
            setStep('error');
            return;
        }

        setBatch(parsed);
        verifyAll(parsed);
    }, []);

    const verifyAll = async (payload: BatchQRPayload) => {
        setStep('verifying');

        // Initialize entries
        const entries: AppEntry[] = payload.apps.map((app) => ({
            rpId: app.rpId,
            sessionId: app.sessionId,
            attestation: null,
            isTrusted: false,
            isChanged: false,
            status: 'pending',
        }));
        setApps(entries);

        // Per-app attestation policy (mirrors connect.tsx):
        //   - inspect() the cert first to detect enclave vs non-enclave (e.g.
        //     a non-enclave RP like github.com is a legitimate batch entry).
        //   - For enclave entries, full verify() against as.privasys.org on
        //     first connect or when the local trusted-apps cache is stale /
        //     a random sample says so.
        //   - For cached-and-fresh enclave entries, trust the local cache
        //     (see REVERIFY_TTL_MS / REVERIFY_RANDOM_P in connect.tsx — kept
        //     in sync with the values there).
        //   - Hard-fail any enclave entry whose AS verification fails.
        // App Attest token is fetched once on demand and reused across all
        // entries that actually need a fresh AS round-trip.
        const REVERIFY_TTL_MS = 24 * 60 * 60 * 1000;
        const REVERIFY_RANDOM_P = 0.1;
        let asToken: string | null = null;
        const getAsTokenLazy = async () => {
            if (asToken) return asToken;
            asToken = await getAttestationServerToken();
            return asToken;
        };

        const results = await Promise.allSettled(
            payload.apps.map(async (app) => {
                const inspectResult = await inspectAttestation(app.rpId);
                const hasMeasurements = !!(inspectResult.mrenclave || inspectResult.mrtd);
                if (!hasMeasurements) {
                    // Non-enclave RP — no attestation to perform.
                    return inspectResult;
                }
                const trustedApp = getApp(app.rpId);
                const cachedMatch =
                    !!trustedApp &&
                    isAttestationMatch(app.rpId, {
                        mrenclave: inspectResult.mrenclave,
                        mrtd: inspectResult.mrtd,
                        codeHash: inspectResult.code_hash,
                        configRoot: inspectResult.config_merkle_root,
                    });
                const cacheAgeMs = trustedApp ? Date.now() - trustedApp.lastVerified * 1000 : Infinity;
                const reverifyDue =
                    !cachedMatch ||
                    cacheAgeMs > REVERIFY_TTL_MS ||
                    Math.random() < REVERIFY_RANDOM_P;
                if (!reverifyDue) {
                    return inspectResult;
                }
                const token = await getAsTokenLazy();
                return verifyAttestation(app.rpId, {
                    tee: inspectResult.tee_type ?? 'sgx',
                    attestation_server: 'https://as.privasys.org',
                    attestation_server_token: token,
                });
            }),
        );

        const updated = entries.map((entry, i) => {
            const result = results[i];
            if (result.status === 'rejected') {
                return { ...entry, status: 'failed' as const, error: result.reason?.message ?? 'Verification failed' };
            }

            const attestation = result.value;
            const trustedApp = getApp(entry.rpId);
            const isMatch = trustedApp
                ? isAttestationMatch(entry.rpId, {
                      mrenclave: attestation.mrenclave,
                      mrtd: attestation.mrtd,
                      codeHash: attestation.code_hash,
                      configRoot: attestation.config_merkle_root,
                  })
                : false;

            return {
                ...entry,
                attestation,
                isTrusted: !!trustedApp && isMatch,
                isChanged: !!trustedApp && !isMatch,
                status: 'verified' as const,
            };
        });

        setApps(updated);

        // If all trusted + within grace period, auto-authenticate
        const allTrusted = updated.every((a) => a.isTrusted);
        if (allTrusted && checkUnlocked()) {
            await authenticateAll(payload, updated);
            return;
        }

        setStep('review');
    };

    const handleApprove = useCallback(async () => {
        if (!batch) return;
        setStep('biometric');

        const appNames = apps
            .filter((a) => a.status === 'verified')
            .map((a) => a.rpId)
            .join(', ');

        const result = await LocalAuthentication.authenticateAsync({
            promptMessage: `Sign in to ${appNames}`,
            fallbackLabel: 'Use Passcode',
            cancelLabel: 'Cancel',
            disableDeviceFallback: false,
        });

        if (!result.success) {
            setError('Authentication cancelled');
            setStep('error');
            return;
        }

        if (gracePeriodSec > 0) {
            setUnlocked(gracePeriodSec * 1000);
        }

        await authenticateAll(batch, apps);
    }, [batch, apps, gracePeriodSec]);

    const authenticateAll = async (payload: BatchQRPayload, entries: AppEntry[]) => {
        setStep('authenticating');

        const updatedApps = [...entries];

        // Process each app sequentially (hardware key can only sign one at a time)
        for (let i = 0; i < updatedApps.length; i++) {
            const app = updatedApps[i];
            if (app.status === 'failed') continue;

            try {
                const credential = getCredentialForRp(app.rpId);
                let sessionToken: string;
                let pendingCredential: Parameters<typeof addCredential>[0] | null = null;

                if (credential) {
                    const result = await fido2.authenticate(
                        app.rpId,
                        credential.keyAlias,
                        credential.credentialId,
                        app.sessionId,
                    );
                    sessionToken = result.sessionToken;
                } else {
                    const keyAlias = `fido2-${app.rpId}`;
                    const result = await fido2.register(app.rpId, keyAlias, app.sessionId);
                    sessionToken = result.sessionToken;

                    // Persist after relay succeeds (below)
                    pendingCredential = {
                        credentialId: result.credentialId,
                        rpId: app.rpId,
                        origin: app.rpId,
                        keyAlias,
                        userHandle: result.userHandle,
                        userName: result.userName,
                        registeredAt: Math.floor(Date.now() / 1000),
                    };
                }

                updatedApps[i] = { ...app, status: 'authenticated' };
                setApps([...updatedApps]);

                // Relay token to browser
                setStep('relaying');
                await relaySessionToken(payload.brokerUrl, app.sessionId, sessionToken, pushToken);

                // Relay succeeded — now persist locally
                if (pendingCredential) {
                    addCredential(pendingCredential);

                    if (app.attestation) {
                        addTrustedApp({
                            rpId: app.rpId,
                            origin: app.rpId,
                            mrenclave: app.attestation.mrenclave,
                            mrtd: app.attestation.mrtd,
                            codeHash: app.attestation.code_hash,
                            configRoot: app.attestation.config_merkle_root,
                            teeType: app.attestation.tee_type || 'sgx',
                            lastVerified: Math.floor(Date.now() / 1000),
                            credentialId: pendingCredential.credentialId,
                        });
                    }
                }

                updatedApps[i] = { ...app, status: 'relayed' };
                setApps([...updatedApps]);
            } catch (e: any) {
                updatedApps[i] = { ...app, status: 'failed', error: e.message };
                setApps([...updatedApps]);
            }
        }

        const allDone = updatedApps.every((a) => a.status === 'relayed' || a.status === 'failed');
        const anyFailed = updatedApps.some((a) => a.status === 'failed');

        if (allDone) {
            if (anyFailed) {
                const failures = updatedApps.filter((a) => a.status === 'failed');
                setError(`${failures.length} app(s) failed`);
                setStep('error');
            } else {
                setStep('done');
                setTimeout(() => router.replace('/(tabs)'), 1500);
            }
        }
    };

    const handleReject = () => {
        router.replace('/(tabs)');
    };

    const renderAppItem = ({ item }: { item: AppEntry }) => (
        <View style={styles.appItem}>
            <View style={styles.appRow}>
                <Text style={styles.appName} numberOfLines={1}>
                    {item.rpId}
                </Text>
                <Text style={styles.appStatus}>
                    {item.status === 'pending' && '⏳'}
                    {item.status === 'verified' && (item.isTrusted ? '✓ Trusted' : item.isChanged ? '⚠ Changed' : '🔍 New')}
                    {item.status === 'failed' && '✕ Failed'}
                    {item.status === 'authenticated' && '🔑'}
                    {item.status === 'relayed' && '✓'}
                </Text>
            </View>
            {item.error && <Text style={styles.appError}>{item.error}</Text>}
            {item.attestation && item.status === 'verified' && (
                <Text style={styles.appDetail}>
                    {item.attestation.tee_type?.toUpperCase()} — {item.attestation.valid ? 'Valid' : 'Invalid'}
                </Text>
            )}
        </View>
    );

    return (
        <>
            <Stack.Screen options={{ headerShown: false }} />
            <View style={styles.container}>
                {step === 'verifying' && (
                    <View style={styles.centered}>
                        <ActivityIndicator size="large" color="#007AFF" />
                        <Text style={styles.statusText}>
                            Verifying {apps.length} enclaves...
                        </Text>
                    </View>
                )}

                {step === 'review' && (
                    <ScrollView contentContainerStyle={styles.reviewContainer}>
                        <Text style={styles.title}>Batch Sign-In</Text>
                        <Text style={styles.subtitle}>
                            {apps.filter((a) => a.status === 'verified').length} app(s) verified
                        </Text>

                        <FlatList
                            data={apps}
                            keyExtractor={(item) => item.rpId}
                            renderItem={renderAppItem}
                            scrollEnabled={false}
                            style={styles.appList}
                        />

                        <View style={styles.buttonRow}>
                            <Pressable style={styles.rejectButton} onPress={handleReject}>
                                <Text style={styles.rejectButtonText}>Reject All</Text>
                            </Pressable>
                            <Pressable style={styles.approveButton} onPress={handleApprove}>
                                <Text style={styles.approveButtonText}>Approve All</Text>
                            </Pressable>
                        </View>
                    </ScrollView>
                )}

                {(step === 'biometric' || step === 'authenticating' || step === 'relaying') && (
                    <View style={styles.centered}>
                        <ActivityIndicator size="large" color="#007AFF" />
                        <Text style={styles.statusText}>
                            {step === 'biometric' && 'Waiting for biometrics...'}
                            {step === 'authenticating' && 'Authenticating...'}
                            {step === 'relaying' && 'Sending to browser...'}
                        </Text>
                        <FlatList
                            data={apps}
                            keyExtractor={(item) => item.rpId}
                            renderItem={renderAppItem}
                            scrollEnabled={false}
                            style={[styles.appList, { marginTop: 24 }]}
                        />
                    </View>
                )}

                {step === 'done' && (
                    <View style={styles.centered}>
                        <Text style={styles.checkmark}>✓</Text>
                        <Text style={styles.title}>All Connected</Text>
                        <Text style={styles.subtitle}>
                            {apps.filter((a) => a.status === 'relayed').length} app(s) authenticated.
                        </Text>
                    </View>
                )}

                {step === 'error' && (
                    <View style={styles.centered}>
                        <Text style={styles.errorIcon}>✕</Text>
                        <Text style={styles.title}>Batch Auth Failed</Text>
                        {error && <Text style={styles.errorText}>{error}</Text>}
                        <FlatList
                            data={apps.filter((a) => a.status === 'failed')}
                            keyExtractor={(item) => item.rpId}
                            renderItem={renderAppItem}
                            scrollEnabled={false}
                            style={styles.appList}
                        />
                        <Pressable style={styles.secondaryButton} onPress={handleReject}>
                            <Text style={styles.secondaryButtonText}>Go back</Text>
                        </Pressable>
                    </View>
                )}
            </View>
        </>
    );
}

const styles = StyleSheet.create({
    container: { flex: 1 },
    centered: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        paddingHorizontal: 20,
    },
    reviewContainer: { padding: 20, paddingTop: 80 },
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
    },
    appList: { width: '100%', marginBottom: 20 },
    appItem: {
        backgroundColor: 'rgba(128,128,128,0.08)',
        borderRadius: 10,
        padding: 14,
        marginBottom: 8,
    },
    appRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        backgroundColor: 'transparent',
    },
    appName: { fontSize: 15, fontWeight: '600', flex: 1 },
    appStatus: { fontSize: 13, opacity: 0.7, marginLeft: 8 },
    appDetail: { fontSize: 12, opacity: 0.5, marginTop: 4 },
    appError: { fontSize: 12, color: '#FF3B30', marginTop: 4 },
    buttonRow: { flexDirection: 'row', justifyContent: 'space-between', gap: 12 },
    approveButton: {
        flex: 1,
        backgroundColor: '#34C759',
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center',
    },
    approveButtonText: { color: '#fff', fontSize: 17, fontWeight: '600' },
    rejectButton: {
        flex: 1,
        backgroundColor: 'rgba(128,128,128,0.2)',
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center',
    },
    rejectButtonText: { fontSize: 17, fontWeight: '600' },
    secondaryButton: {
        backgroundColor: '#007AFF',
        borderRadius: 12,
        paddingHorizontal: 32,
        paddingVertical: 14,
        minWidth: 160,
        alignItems: 'center',
    },
    secondaryButtonText: { color: '#fff', fontSize: 17, fontWeight: '600' },
});
