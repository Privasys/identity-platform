// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Connect flow — the core authentication journey:
 * 1. Parse QR/push payload (origin, sessionId, rpId, brokerUrl)
 * 2. RA-TLS attestation verification
 * 3. FIDO2 registration or authentication
 * 4. Relay session token to browser via broker
 *
 * Entry points pass `source` to control UX:
 * - `source='qr'`   — user scanned a QR code; skip "Sign in?" confirmation,
 *                      go straight to biometric → FIDO2.
 * - `source='push'`  — push notification tap; show "Sign in?" confirmation
 *                      first so the user can reject unexpected requests.
 */

import { useRouter, useLocalSearchParams, Stack } from 'expo-router';
import { useState, useEffect, useCallback, useRef } from 'react';
import {
    StyleSheet,
    Pressable,
    ActivityIndicator,
    ScrollView,
    View as RNView,
    TextInput,
    Alert,
    KeyboardAvoidingView,
    Platform,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Ionicons } from '@expo/vector-icons';
import * as WebBrowser from 'expo-web-browser';
import { sha256 } from '@noble/hashes/sha2.js';

import { Text, View } from '@/components/Themed';
import { useExpoPushToken } from '@/hooks/useExpoPushToken';
import { getAttestationServerToken } from '@/services/app-attest';
import { inspectAttestation, verifyAttestation } from '@/services/attestation';
import { relaySessionToken } from '@/services/broker';
import { deriveAppSub, generateDid, generatePairwiseSeed, generateCanonicalDid } from '@/services/did';
import * as fido2 from '@/services/fido2';
import { getClientId, linkIdentityProvider, PROVIDERS, type ProviderConfig } from '@/services/identity';
import { attributeLabel, CANONICAL_KEYS, getProfileValue, setProfileValue } from '@/services/attributes';
import { useAuthStore } from '@/stores/auth';
import { useConsentStore } from '@/stores/consent';
import { useProfileStore } from '@/stores/profile';
import { useSessionsStore } from '@/stores/sessions';
import { useSettingsStore } from '@/stores/settings';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';

function appName(rpId: string): string {
    const dot = rpId.indexOf('.');
    return dot > 0 ? rpId.substring(0, dot) : rpId;}

/**
 * Derive a stable hex digest over the verified attestation. This is the
 * `quote_hash` claim the wallet binds into the WebAuthn challenge — the
 * IdP echoes it through into the issued JWT so a relying party can
 * cryptographically check it picked the enclave the wallet attested.
 *
 * Mirror of any downstream verifier that recomputes the same digest
 * from its own AttestationResult.
 */
function deriveQuoteHash(att: AttestationResult): string {
    const fields: string[] = [
        att.tee_type ?? '',
        att.mrenclave ?? '',
        att.mrsigner ?? '',
        att.mrtd ?? '',
        att.code_hash ?? '',
        att.config_merkle_root ?? '',
        att.attestation_servers_hash ?? '',
    ];
    const bytes = sha256(new TextEncoder().encode(fields.join(':')));
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i]!.toString(16).padStart(2, '0');
    }
    return hex;
}

function friendlyBrowser(ua?: string): string | null {
    if (!ua) return null;
    const browser =
        /Edg\//.test(ua) ? 'Edge' :
        /OPR\/|Opera/.test(ua) ? 'Opera' :
        /Chrome\//.test(ua) ? 'Chrome' :
        /Safari\//.test(ua) && !/Chrome/.test(ua) ? 'Safari' :
        /Firefox\//.test(ua) ? 'Firefox' : null;
    const os =
        /Windows/.test(ua) ? 'Windows' :
        /Mac OS X/.test(ua) ? 'macOS' :
        /Linux/.test(ua) ? 'Linux' :
        /Android/.test(ua) ? 'Android' : null;
    if (browser && os) return `${browser} on ${os}`;
    if (browser) return browser;
    return null;
}

/**
 * Resolve profile attributes based on what the app requested via
 * `requestedAttributes` in the QR payload.  Returns undefined if
 * nothing was requested or the profile is empty.
 */
async function resolveRequestedAttributes(
    payload: QRPayload,
    profile: import('@/stores/profile').UserProfile | null,
): Promise<Record<string, string> | undefined> {
    const requested = payload.requestedAttributes;
    if (!requested?.length || !profile) return undefined;

    const attrs: Record<string, string> = {};

    for (const attr of requested) {
        if (attr === 'sub') {
            if (profile.pairwiseSeed) {
                try { attrs.sub = await deriveAppSub(profile.pairwiseSeed, payload.rpId); } catch {}
            }
            continue;
        }
        const value = getProfileValue(profile, attr);
        if (value) attrs[attr] = value;
    }

    return Object.keys(attrs).length > 0 ? attrs : undefined;
}

/**
 * Determine which requested attributes are missing from the user's profile.
 * Returns the list of attribute keys that the app wants but the profile
 * doesn't have values for. 'sub' is excluded since it's always derivable.
 * Only canonical attributes are accepted — unknown keys are ignored.
 */
function getMissingAttributes(
    payload: QRPayload,
    profile: import('@/stores/profile').UserProfile | null,
): string[] {
    const requested = payload.requestedAttributes;
    if (!requested?.length) return [];

    const missing: string[] = [];
    for (const attr of requested) {
        if (attr === 'sub') continue;
        if (!CANONICAL_KEYS.has(attr)) continue;
        if (!profile || !getProfileValue(profile, attr)) {
            missing.push(attr);
        }
    }
    return missing;
}

type FlowStep =
    | 'verifying'
    | 'confirm'
    | 'attestation'
    | 'attestation-changed'
    | 'biometric'
    | 'authenticating'
    | 'acquire-attributes'
    | 'relaying'
    | 'done'
    | 'error';

interface QRPayload {
    origin: string;
    sessionId: string;
    rpId: string;
    brokerUrl: string;
    userAgent?: string;
    requestedAttributes?: string[];
    appName?: string;
    privacyPolicyUrl?: string;
    clientIP?: string;
    /** When set to 'session-relay', the wallet must call /__privasys/session-bootstrap
     *  with `sdkPub` before the FIDO2 ceremony so the IdP can bind the issued
     *  JWT to a sealed-CBOR transport session. */
    mode?: 'session-relay' | 'standard';
    /** SDK ephemeral P-256 SEC1 uncompressed public key, base64url. Required
     *  when mode==='session-relay'. */
    sdkPub?: string;
    /** Hostname (no scheme) of the enclave app that hosts
     *  `/__privasys/session-bootstrap`. Different from `origin`/`rpId`,
     *  which point at the IdP. Required when mode==='session-relay'. */
    appHost?: string;
    /** Per-session replay nonce (base64url). When omitted we fall back to
     *  `sessionId` for the session-relay challenge binding. */
    nonce?: string;
}

export default function ConnectScreen() {
    const router = useRouter();
    const params = useLocalSearchParams<{
        payload?: string; // JSON-encoded QRPayload
        serviceUrl?: string; // Legacy fallback
        source?: 'qr' | 'push'; // How the flow was initiated
    }>();
    const isFromPush = params.source === 'push';
    const pushToken = useExpoPushToken();

    // Stores
    const { addCredential, removeCredential, getCredentialForRp, checkUnlocked, setUnlocked } = useAuthStore();
    const { getApp, isAttestationMatch, addOrUpdate: addTrustedApp } = useTrustedAppsStore();
    const { gracePeriodSec } = useSettingsStore();
    const addRelaySession = useSessionsStore((s) => s.add);
    const profile = useProfileStore((s) => s.profile);

    // State
    const [step, setStep] = useState<FlowStep>('verifying');
    const [error, setError] = useState<string | null>(null);
    const [attestation, setAttestation] = useState<AttestationResult | null>(null);
    // Mirror of `attestation` updated synchronously alongside setAttestation
    // so callbacks invoked in the same tick (e.g. doAuthenticate fired right
    // after setAttestation in startFlow) can read the freshly-verified value
    // without waiting for React to commit. session-relay binds quote_hash
    // into the FIDO2 challenge, so reading a stale (null) closure value
    // tripped "session-relay mode requires verified attestation" even on
    // the happy trusted-app path.
    const attestationRef = useRef<AttestationResult | null>(null);
    const [qr, setQr] = useState<QRPayload | null>(null);
    const [isTrusted, setIsTrusted] = useState(false);
    const [attestationChanged, setAttestationChanged] = useState(false);
    const hasStarted = useRef(false);

    // Attribute acquisition state — holds FIDO2 result while user provides missing profile data
    const [missingAttrs, setMissingAttrs] = useState<string[]>([]);
    const pendingRelay = useRef<{
        payload: QRPayload;
        sessionToken: string;
        /** Only set for registration (not authentication) */
        credential?: {
            credentialId: string;
            keyAlias: string;
            userHandle?: string;
            userName?: string;
            serverRpId?: string;
        };
    } | null>(null);

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
            // In session-relay mode the meaningful enclave is the AI app host
            // (where the sealed-CBOR transport terminates and where the
            // bound JWT will be presented). The IdP at `payload.origin`
            // brokers the FIDO2 ceremony but never sees the sealed bytes,
            // so attesting it would not constrain the relying party.
            const attestationTarget =
                payload.mode === 'session-relay' && payload.appHost
                    ? payload.appHost
                    : payload.origin;
            console.log(`[CONNECT] startFlow — verifying attestation for ${attestationTarget}` +
                (attestationTarget !== payload.origin ? ` (session-relay; origin=${payload.origin})` : ''));
            try {
                let result: AttestationResult;
                try {
                    // Obtain an AS token via App Attest, then verify through the attestation server
                    const asToken = await getAttestationServerToken();
                    console.log('[CONNECT] obtained AS token, calling verify()');
                    result = await verifyAttestation(attestationTarget, {
                        tee: 'sgx',
                        attestation_server: 'https://as.privasys.org',
                        attestation_server_token: asToken,
                    });
                } catch (verifyErr: any) {
                    // Fallback to inspect-only (e.g. simulator, App Attest unavailable)
                    console.warn(`[CONNECT] verify() unavailable, falling back to inspect: ${verifyErr.message}`);
                    result = await inspectAttestation(attestationTarget);
                }
                console.log(`[CONNECT] attestation OK — mrenclave=${result.mrenclave?.substring(0, 16)}...`);

                // Non-enclave backend: no enclave measurements → skip attestation approval.
                if (!result.mrenclave && !result.mrtd) {
                    console.log('[CONNECT] no enclave measurements — skipping attestation approval');
                    const credential = getCredentialForRp(payload.rpId);
                    if (credential) {
                        setIsTrusted(true);
                        if (isFromPush && !checkUnlocked()) {
                            // Push-initiated outside grace period: show "Sign in?" confirmation
                            setStep('confirm');
                            return;
                        }
                        // QR-initiated or within grace period: go straight to FIDO2.
                        // NativeKeys.sign() handles biometric — no app-level prompt needed.
                        await doAuthenticate(payload, credential.keyAlias, credential.credentialId, credential.serverRpId);
                        return;
                    }
                    // First time — register (FIDO2 handles biometric via NativeKeys)
                    await doRegister(payload);
                    return;
                }

                setAttestation(result);
                attestationRef.current = result;

                // The trusted-apps store is keyed by the entity whose
                // measurements we just verified — that's `attestationTarget`,
                // not necessarily `payload.rpId`. (FIDO2 credentials remain
                // keyed by rpId; only the enclave-trust record moves.)
                const trustKey = attestationTarget;
                const trustedApp = getApp(trustKey);
                if (
                    trustedApp &&
                    isAttestationMatch(trustKey, {
                        mrenclave: result.mrenclave,
                        mrtd: result.mrtd,
                        codeHash: result.code_hash,
                        configRoot: result.config_merkle_root
                    })
                ) {
                    setIsTrusted(true);
                    const credential = getCredentialForRp(payload.rpId);
                    if (credential) {
                        if (isFromPush && !checkUnlocked()) {
                            // Push-initiated outside grace period: show "Sign in?" confirmation
                            setStep('confirm');
                            return;
                        }
                        // QR-initiated or within grace period: go straight to FIDO2.
                        // NativeKeys.sign() handles biometric — no app-level prompt needed.
                        await doAuthenticate(payload, credential.keyAlias, credential.credentialId, credential.serverRpId);
                        return;
                    }
                    setStep('attestation');
                    return;
                }

                if (trustedApp) {
                    setAttestationChanged(true);
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
        [getApp, isAttestationMatch, getCredentialForRp, checkUnlocked, gracePeriodSec]
    );

    const handleConfirm = useCallback(async () => {
        if (!qr) return;
        const credential = getCredentialForRp(qr.rpId);
        if (!credential) return;

        // Go directly to FIDO2 — NativeKeys.sign() handles biometric.
        await doAuthenticate(qr, credential.keyAlias, credential.credentialId, credential.serverRpId);
    }, [qr]);

    const handleApprove = useCallback(async () => {
        if (!qr || !attestation) return;

        // If attestation changed, the enclave has a new KV store and our
        // old credential no longer exists server-side.  Remove it and
        // re-register so the user gets a fresh credential.
        const credential = getCredentialForRp(qr.rpId);
        if (credential && attestationChanged) {
            console.log('[CONNECT] attestation changed — removing old credential and re-registering');
            removeCredential(credential.credentialId);
            await doRegister(qr);
        } else if (credential) {
            await doAuthenticate(qr, credential.keyAlias, credential.credentialId, credential.serverRpId);
        } else {
            await doRegister(qr);
        }
    }, [qr, attestation, attestationChanged]);

    /** Build the wallet-side session-relay argument from the QR payload
     *  and the verified attestation, or return undefined when the QR did
     *  not opt in. Shared by doRegister and doAuthenticate so first-time
     *  users get the same sealed-transport binding as returning users. */
    const buildSessionRelayArg = (
        payload: QRPayload,
    ): { sdkPub: string; appHost: string; quoteHash: string; nonce: string } | undefined => {
        if (payload.mode !== 'session-relay' || !payload.sdkPub) return undefined;
        if (!payload.appHost) {
            throw new Error('session-relay mode requires appHost');
        }
        const att = attestationRef.current ?? attestation;
        if (!att) {
            throw new Error('session-relay mode requires verified attestation');
        }
        return {
            sdkPub: payload.sdkPub,
            appHost: payload.appHost,
            quoteHash: deriveQuoteHash(att),
            // The QR-supplied nonce is the canonical replay window for
            // this session. Fall back to the broker session id when
            // the QR is still on v1 (no `nonce` field).
            nonce: payload.nonce ?? payload.sessionId,
        };
    };

    const doRegister = async (payload: QRPayload) => {
        setStep('authenticating');
        console.log(`[CONNECT] doRegister — origin=${payload.origin}, rpId=${payload.rpId}`);
        try {
            const keyAlias = `fido2-${payload.rpId}`;
            const currentProfile = useProfileStore.getState().profile;
            // Build session-relay binding (mirror of doAuthenticate). Without
            // this, first-time users get a vanilla passkey and no sealed
            // session, so the chat UI cannot reach the enclave and the
            // Home tab never shows a SESSIONS row.
            const sessionRelayArg = buildSessionRelayArg(payload);
            const result = await fido2.register(
                payload.origin,
                keyAlias,
                payload.sessionId,
                currentProfile?.displayName,
                undefined,
                sessionRelayArg,
            );

            // Check for missing attributes before relaying
            const missing = getMissingAttributes(payload, currentProfile);
            if (missing.length > 0) {
                console.log(`[CONNECT] missing attributes: ${missing.join(', ')} — prompting acquisition`);
                pendingRelay.current = {
                    payload,
                    sessionToken: result.sessionToken,
                    credential: {
                        credentialId: result.credentialId,
                        keyAlias,
                        userHandle: result.userHandle,
                        userName: result.userName,
                        serverRpId: result.serverRpId,
                    },
                };
                setMissingAttrs(missing);
                setStep('acquire-attributes');
                return;
            }

            // Relay to browser BEFORE persisting — if relay fails the
            // credential must not appear in "Connected Services".
            setStep('relaying');

            // Resolve only the attributes the app actually requested.
            const attributes = await resolveRequestedAttributes(payload, profile);

            await relaySessionToken(
                payload.brokerUrl,
                payload.sessionId,
                result.sessionToken,
                pushToken,
                attributes,
                result.sessionRelay,
            );

            // Relay succeeded — now persist locally.
            persistCredentialAndTrust(payload, result.credentialId, keyAlias, result.userHandle, result.userName, result.serverRpId);

            // Surface the live sealed session on the Home screen so the
            // user sees the relay countdown next to the connected service.
            if (result.sessionRelay) {
                addRelaySession({
                    sessionId: result.sessionRelay.sessionId,
                    rpId: payload.rpId,
                    origin: payload.origin,
                    appName: payload.appName,
                    expiresAt: result.sessionRelay.expiresAt,
                    startedAt: Math.floor(Date.now() / 1000),
                });
            }

            // Start biometric grace period (skips push confirmation for subsequent auths).
            if (gracePeriodSec > 0) setUnlocked(gracePeriodSec * 1000);

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
        serverRpId?: string
    ) => {
        setStep('authenticating');
        console.log(`[CONNECT] doAuthenticate — origin=${payload.origin}, credentialId=${credentialId.substring(0, 16)}...`);
        try {
            // Build session-relay binding inputs only when the QR opted in.
            // The IdP recomputes SHA-256(domain || nonce || sdk_pub ||
            // quote_hash || enc_pub || session_id) and rejects on
            // mismatch, so the issued JWT proves the wallet attested
            // exactly the listed quote.
            const sessionRelayArg = buildSessionRelayArg(payload);

            const result = await fido2.authenticate(
                payload.origin,
                keyAlias,
                credentialId,
                payload.sessionId,
                serverRpId,
                sessionRelayArg,
            );

            // Check for missing attributes before relaying
            const currentProfile = useProfileStore.getState().profile;
            const missing = getMissingAttributes(payload, currentProfile);
            if (missing.length > 0) {
                console.log(`[CONNECT] missing attributes: ${missing.join(', ')} — prompting acquisition`);
                pendingRelay.current = { payload, sessionToken: result.sessionToken };
                setMissingAttrs(missing);
                setStep('acquire-attributes');
                return;
            }

            setStep('relaying');

            // Resolve only the attributes the app actually requested.
            const attributes = await resolveRequestedAttributes(payload, profile);

            await relaySessionToken(
                payload.brokerUrl,
                payload.sessionId,
                result.sessionToken,
                pushToken,
                attributes,
                result.sessionRelay,
            );

            // Phase E: when the SDK opted into the sealed session-relay
            // bootstrap, surface the live session on the Home screen
            // until the enclave-side binding expires.
            if (result.sessionRelay) {
                addRelaySession({
                    sessionId: result.sessionRelay.sessionId,
                    rpId: payload.rpId,
                    origin: payload.origin,
                    appName: payload.appName,
                    expiresAt: result.sessionRelay.expiresAt,
                    startedAt: Math.floor(Date.now() / 1000),
                });
            }

            // Start biometric grace period (skips push confirmation for subsequent auths).
            if (gracePeriodSec > 0) setUnlocked(gracePeriodSec * 1000);

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

    /** Persist credential and trusted app after a successful relay. */
    const persistCredentialAndTrust = (
        payload: QRPayload,
        credentialId: string,
        keyAlias: string,
        userHandle = '',
        userName = '',
        serverRpId?: string,
    ) => {
        addCredential({
            credentialId,
            rpId: payload.rpId,
            origin: payload.origin,
            keyAlias,
            userHandle,
            userName,
            registeredAt: Math.floor(Date.now() / 1000),
            serverRpId,
        });

        // Store the trust record under the entity that was actually attested
        // (appHost in session-relay mode, otherwise origin) so that the
        // measurements we persist correspond to the host they describe.
        const trustKey =
            payload.mode === 'session-relay' && payload.appHost
                ? payload.appHost
                : payload.origin;

        if (attestation) {
            addTrustedApp({
                rpId: trustKey,
                origin: trustKey,
                mrenclave: attestation.mrenclave,
                mrtd: attestation.mrtd,
                codeHash: attestation.code_hash,
                configRoot: attestation.config_merkle_root,
                teeType: attestation.tee_type || 'sgx',
                lastVerified: Math.floor(Date.now() / 1000),
                credentialId,
            });
        } else {
            addTrustedApp({
                rpId: trustKey,
                origin: trustKey,
                teeType: 'none',
                lastVerified: Math.floor(Date.now() / 1000),
                credentialId,
            });
        }
    };

    /**
     * Called when the user has finished providing missing attributes.
     * Re-reads the profile, resolves attributes, and completes the relay.
     */
    const handleAttributesAcquired = useCallback(async () => {
        const pending = pendingRelay.current;
        if (!pending) return;

        // Re-check: are attributes still missing?
        const updatedProfile = useProfileStore.getState().profile;
        const stillMissing = getMissingAttributes(pending.payload, updatedProfile);
        if (stillMissing.length > 0) {
            Alert.alert(
                'Missing information',
                `Please provide: ${stillMissing.map((k) => attributeLabel(k)).join(', ')}`,
            );
            return;
        }

        setStep('relaying');
        try {
            const attributes = await resolveRequestedAttributes(pending.payload, updatedProfile);

            await relaySessionToken(
                pending.payload.brokerUrl,
                pending.payload.sessionId,
                pending.sessionToken,
                pushToken,
                attributes,
            );

            // For registration, persist the credential now
            if (pending.credential) {
                persistCredentialAndTrust(
                    pending.payload,
                    pending.credential.credentialId,
                    pending.credential.keyAlias,
                    pending.credential.userHandle,
                    pending.credential.userName,
                    pending.credential.serverRpId,
                );
            }

            pendingRelay.current = null;
            setStep('done');
            setTimeout(() => router.replace('/(tabs)'), 1500);
        } catch (e: any) {
            console.error(`[CONNECT] relay after acquisition FAILED:`, e.message, e);
            setError(`Failed to complete sign-in: ${e.message}`);
            setStep('error');
        }
    }, [pushToken]);

    return (
        <>
            <Stack.Screen options={{ headerShown: false }} />
            <View style={styles.container}>
                {step === 'verifying' && (
                    <View style={styles.centered}>
                        <ActivityIndicator size="large" color="#007AFF" />
                        <Text style={styles.statusText}>Verifying server attestation...</Text>
                    </View>
                )}

                {step === 'confirm' && qr && (
                    <View style={styles.confirmContainer}>
                        <View style={styles.confirmContent}>
                            <View style={styles.confirmIcon}>
                                <Text style={styles.confirmIconText}>{(qr.appName || appName(qr.rpId)).charAt(0).toUpperCase()}</Text>
                            </View>
                            <Text style={styles.title}>Sign-in request</Text>
                            <Text style={styles.confirmAppName}>{qr.appName || appName(qr.rpId)}</Text>
                            <Text style={styles.confirmDomain}>{qr.rpId}</Text>
                            {(friendlyBrowser(qr.userAgent) || qr.clientIP) && (
                                <Text style={styles.confirmHint}>
                                    {[friendlyBrowser(qr.userAgent), qr.clientIP].filter(Boolean).join(' · ')}
                                </Text>
                            )}
                        </View>
                        <View style={styles.confirmActions}>
                            <Pressable style={styles.confirmDenyButton} onPress={handleReject}>
                                <Text style={styles.confirmDenyButtonText}>Deny</Text>
                            </Pressable>
                            <Pressable style={styles.confirmApproveButton} onPress={handleConfirm}>
                                <Text style={styles.confirmApproveButtonText}>Approve</Text>
                            </Pressable>
                        </View>
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

                {step === 'acquire-attributes' && qr && (
                    <AttributeAcquisitionView
                        rpId={qr.rpId}
                        appName={qr.appName}
                        privacyPolicyUrl={qr.privacyPolicyUrl}
                        missingAttributes={missingAttrs}
                        attestation={attestation}
                        onComplete={handleAttributesAcquired}
                        onCancel={handleReject}
                    />
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
    const [detailsOpen, setDetailsOpen] = useState(false);
    const insets = useSafeAreaInsets();
    const appType = attestation.tee_type === 'sgx' ? 'WASM Application' : 'Container Application';
    const teeColor = attestation.tee_type === 'sgx' ? '#34E89E' : '#00BCF2';

    return (
        <RNView style={{ flex: 1 }}>
            <ScrollView contentContainerStyle={[styles.attestationContainer, { paddingBottom: 100 + insets.bottom }]}>
                {isChanged && (
                    <View style={styles.warningBanner}>
                        <Text style={styles.warningText}>
                            ⚠ This app's attestation has changed since you last verified it.
                        </Text>
                    </View>
                )}

                <Text style={styles.title}>{isChanged ? 'App Changed' : 'Verify Enclave'}</Text>
                <Text style={styles.attestationAppName}>{appName(rpId)}</Text>
                <Text style={styles.attestationOrigin}>{rpId}</Text>

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

                {/* Collapsible details toggle */}
                <Pressable
                    style={styles.detailsToggle}
                    onPress={() => setDetailsOpen(!detailsOpen)}
                >
                    <Text style={styles.detailsToggleText}>
                        {detailsOpen ? 'Hide details' : 'Show attestation details'}
                    </Text>
                    <Text style={styles.detailsToggleIcon}>{detailsOpen ? '▲' : '▼'}</Text>
                </Pressable>

                {detailsOpen && (
                    <>
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
                    </>
                )}
            </ScrollView>

            {/* Fixed bottom action buttons */}
            <RNView style={[styles.bottomActions, { paddingBottom: Math.max(insets.bottom, 20) }]}>
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
            </RNView>
        </RNView>
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

// ── Attribute acquisition view ──────────────────────────────────────────

const PROVIDER_ICONS: Record<string, keyof typeof Ionicons.glyphMap> = {
    google: 'logo-google',
    microsoft: 'logo-microsoft',
    github: 'logo-github',
    linkedin: 'logo-linkedin',
};

function AttributeAcquisitionView({
    rpId,
    appName: appNameProp,
    privacyPolicyUrl,
    missingAttributes,
    attestation,
    onComplete,
    onCancel,
}: {
    rpId: string;
    appName?: string;
    privacyPolicyUrl?: string;
    missingAttributes: string[];
    attestation: AttestationResult | null;
    onComplete: () => void;
    onCancel: () => void;
}) {
    const insets = useSafeAreaInsets();
    const { updateProfile, setAttribute, createProfile } = useProfileStore();
    const profile = useProfileStore((s) => s.profile);

    const [mode, setMode] = useState<'choose' | 'manual'>('choose');
    const [linkingProvider, setLinkingProvider] = useState<string | null>(null);
    const [manualValues, setManualValues] = useState<Record<string, string>>({});
    const profileCreated = useRef(false);

    // Auto-create a bare profile if one doesn't exist yet
    useEffect(() => {
        if (profile || profileCreated.current) return;
        profileCreated.current = true;
        (async () => {
            try {
                const did = await generateDid();
                const pairwiseSeed = await generatePairwiseSeed();
                const canonicalDid = await generateCanonicalDid(pairwiseSeed);
                useProfileStore.getState().createProfile({
                    displayName: '',
                    email: '',
                    avatarUri: '',
                    locale: '',
                    did,
                    canonicalDid,
                    pairwiseSeed,
                    linkedProviders: [],
                    attributes: [],
                });
            } catch (e: any) {
                console.error('[CONNECT] failed to auto-create profile:', e.message);
            }
        })();
    }, [profile]);

    // Check if all missing attributes are now present in the profile
    const stillMissing = missingAttributes.filter(
        (attr) => !profile || !getProfileValue(profile, attr),
    );

    const handleLinkProvider = async (providerKey: string) => {
        setLinkingProvider(providerKey);
        try {
            const providerTemplate = PROVIDERS[providerKey];
            if (!providerTemplate) throw new Error(`Unknown provider: ${providerKey}`);

            const clientId = getClientId(providerKey);
            if (!clientId) {
                Alert.alert(
                    'Not configured',
                    `OAuth client ID for ${providerTemplate.displayName} is not configured yet.`,
                );
                return;
            }

            const config: ProviderConfig = { ...providerTemplate, clientId };
            const result = await linkIdentityProvider(config);

            // Update profile with normalised provider data
            const store = useProfileStore.getState();
            store.linkProvider(result.provider);

            for (const attr of result.seedAttributes) {
                // Only seed if the profile doesn't already have this value.
                const existing = profile ? getProfileValue(profile, attr.key) : undefined;
                if (!existing) {
                    setProfileValue(store, attr.key, attr.value, 'provider', {
                        sourceProvider: config.provider,
                        verified: attr.verified,
                        verifications: attr.verifications,
                    });
                }
            }
        } catch (e: any) {
            if (e.message !== 'Authentication cancelled') {
                Alert.alert('Link failed', e.message);
            }
        } finally {
            setLinkingProvider(null);
        }
    };

    const handleManualSave = () => {
        const store = useProfileStore.getState();
        for (const attr of missingAttributes) {
            const value = manualValues[attr]?.trim();
            if (!value) continue;
            setProfileValue(store, attr, value, 'manual');
        }
    };

    const displayAppName = appNameProp || appName(rpId);
    const manualAllFilled = missingAttributes.every((attr) => manualValues[attr]?.trim());

    const handleContinue = () => {
        // Log consent in consent history
        useConsentStore.getState().addRecord({
            id: `attr-acq-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
            rpId,
            origin: rpId,
            appName: displayAppName,
            requestedAttributes: missingAttributes,
            approvedAttributes: missingAttributes,
            deniedAttributes: [],
            decision: 'approved',
            persistent: false,
            teeType: attestation?.tee_type ?? 'none',
            enclaveMeasurement: attestation?.mrenclave ?? attestation?.mrtd ?? '',
            codeHash: attestation?.code_hash ?? '',
            consentedAt: Math.floor(Date.now() / 1000),
            expiresAt: 0,
        });
        onComplete();
    };

    return (
        <KeyboardAvoidingView
            style={{ flex: 1 }}
            behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        >
            <RNView style={{ flex: 1 }}>
                <ScrollView
                    contentContainerStyle={[acqStyles.container, { paddingBottom: 100 + insets.bottom }]}
                    keyboardShouldPersistTaps="handled"
                >
                    <RNView style={acqStyles.iconContainer}>
                        <Ionicons name="person-add-outline" size={36} color="#007AFF" />
                    </RNView>

                    <Text style={styles.title}>Profile needed</Text>
                    <Text style={acqStyles.description}>
                        <Text style={acqStyles.bold}>{displayAppName}</Text>
                        {' needs the following to complete sign-in:'}
                    </Text>

                    {/* Data sharing notice */}
                    <RNView style={acqStyles.privacyNotice}>
                        <Ionicons name="shield-outline" size={16} color="#F59E0B" />
                        <Text style={acqStyles.privacyNoticeText}>
                            These attributes will be shared with{' '}
                            <Text style={acqStyles.bold}>{displayAppName}</Text>
                            {' and will be under their control.'}
                        </Text>
                    </RNView>

                    {privacyPolicyUrl ? (
                        <Pressable
                            style={acqStyles.privacyLink}
                            onPress={() => WebBrowser.openBrowserAsync(privacyPolicyUrl)}
                        >
                            <Ionicons name="document-text-outline" size={14} color="#007AFF" />
                            <Text style={acqStyles.privacyLinkText}>Read privacy policy</Text>
                        </Pressable>
                    ) : null}

                    {/* Show what's needed */}
                    <RNView style={acqStyles.attributeList}>
                        {missingAttributes.map((attr) => {
                            const isFilled = !stillMissing.includes(attr);
                            return (
                                <RNView key={attr} style={acqStyles.attributeRow}>
                                    <Ionicons
                                        name={isFilled ? 'checkmark-circle' : 'ellipse-outline'}
                                        size={20}
                                        color={isFilled ? '#34C759' : '#94A3B8'}
                                    />
                                    <Text style={[acqStyles.attributeLabel, isFilled && acqStyles.attributeFilled]}>
                                        {attributeLabel(attr)}
                                    </Text>
                                    {isFilled && profile && (
                                        <Text style={acqStyles.attributeValue} numberOfLines={1}>
                                            {getProfileValue(profile, attr) ?? ''}
                                        </Text>
                                    )}
                                </RNView>
                            );
                        })}
                    </RNView>

                    {stillMissing.length === 0 ? (
                        /* All attributes acquired — show continue */
                        <RNView style={acqStyles.readySection}>
                            <Ionicons name="checkmark-circle" size={32} color="#34C759" />
                            <Text style={acqStyles.readyText}>All set! Tap continue to finish signing in.</Text>
                        </RNView>
                    ) : mode === 'choose' ? (
                        /* Provider linking options */
                        <>
                            <Text style={acqStyles.sectionTitle}>Import from an account</Text>
                            {Object.entries(PROVIDERS).map(([key, config]) => {
                                const isLinking = linkingProvider === key;
                                return (
                                    <Pressable
                                        key={key}
                                        style={acqStyles.providerButton}
                                        onPress={() => handleLinkProvider(key)}
                                        disabled={isLinking || linkingProvider !== null}
                                    >
                                        <Ionicons
                                            name={PROVIDER_ICONS[key] ?? 'globe-outline'}
                                            size={20}
                                            color="#FFFFFF"
                                        />
                                        {isLinking ? (
                                            <ActivityIndicator size="small" color="#FFFFFF" />
                                        ) : (
                                            <Text style={acqStyles.providerButtonText}>
                                                Continue with {config.displayName}
                                            </Text>
                                        )}
                                    </Pressable>
                                );
                            })}

                            <RNView style={acqStyles.divider}>
                                <RNView style={acqStyles.dividerLine} />
                                <Text style={acqStyles.dividerText}>or</Text>
                                <RNView style={acqStyles.dividerLine} />
                            </RNView>

                            <Pressable
                                style={acqStyles.manualButton}
                                onPress={() => setMode('manual')}
                            >
                                <Ionicons name="create-outline" size={18} color="#007AFF" />
                                <Text style={acqStyles.manualButtonText}>Enter manually</Text>
                            </Pressable>
                        </>
                    ) : (
                        /* Manual entry form */
                        <>
                            <Text style={acqStyles.sectionTitle}>Enter your information</Text>
                            {missingAttributes.map((attr) => {
                                if (!stillMissing.includes(attr)) return null;
                                const label = attributeLabel(attr);
                                return (
                                    <RNView key={attr} style={acqStyles.inputContainer}>
                                        <Text style={acqStyles.inputLabel}>{label}</Text>
                                        <TextInput
                                            style={acqStyles.input}
                                            value={manualValues[attr] ?? ''}
                                            onChangeText={(v) => setManualValues((prev) => ({ ...prev, [attr]: v }))}
                                            placeholder={attr === 'email' ? 'you@example.com' : `Your ${label.toLowerCase()}`}
                                            placeholderTextColor="#94A3B8"
                                            keyboardType={attr === 'email' ? 'email-address' : 'default'}
                                            autoCapitalize={attr === 'email' ? 'none' : 'words'}
                                            autoComplete={attr === 'email' ? 'email' : attr === 'name' ? 'name' : 'off'}
                                        />
                                    </RNView>
                                );
                            })}

                            <Pressable
                                style={[acqStyles.saveButton, !manualAllFilled && acqStyles.saveButtonDisabled]}
                                onPress={handleManualSave}
                                disabled={!manualAllFilled}
                            >
                                <Text style={acqStyles.saveButtonText}>Save</Text>
                            </Pressable>

                            <Pressable
                                style={acqStyles.backLink}
                                onPress={() => setMode('choose')}
                            >
                                <Text style={acqStyles.backLinkText}>← Import from an account instead</Text>
                            </Pressable>
                        </>
                    )}
                </ScrollView>

                {/* Bottom action buttons */}
                <RNView style={[acqStyles.bottomActions, { paddingBottom: Math.max(insets.bottom, 20) }]}>
                    <RNView style={styles.buttonRow}>
                        <Pressable style={styles.rejectButton} onPress={onCancel}>
                            <Text style={styles.rejectButtonText}>Cancel</Text>
                        </Pressable>
                        <Pressable
                            style={[styles.approveButton, stillMissing.length > 0 && acqStyles.continueDisabled]}
                            onPress={handleContinue}
                            disabled={stillMissing.length > 0}
                        >
                            <Text style={styles.approveButtonText}>Continue</Text>
                        </Pressable>
                    </RNView>
                </RNView>
            </RNView>
        </KeyboardAvoidingView>
    );
}

const acqStyles = StyleSheet.create({
    container: { padding: 20, paddingTop: 80 },
    iconContainer: {
        width: 72,
        height: 72,
        borderRadius: 20,
        backgroundColor: 'rgba(0,122,255,0.1)',
        alignItems: 'center',
        justifyContent: 'center',
        alignSelf: 'center',
        marginBottom: 16,
    },
    description: {
        fontSize: 15,
        color: '#64748B',
        textAlign: 'center',
        marginBottom: 24,
        lineHeight: 22,
    },
    bold: { fontWeight: '600', color: '#1E293B' },
    privacyNotice: {
        flexDirection: 'row',
        alignItems: 'flex-start',
        gap: 8,
        backgroundColor: '#FFFBEB',
        borderRadius: 10,
        padding: 12,
        marginBottom: 8,
    },
    privacyNoticeText: {
        flex: 1,
        fontSize: 13,
        color: '#92400E',
        lineHeight: 18,
    },
    privacyLink: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        marginBottom: 16,
        paddingVertical: 4,
    },
    privacyLinkText: {
        fontSize: 13,
        color: '#007AFF',
        fontWeight: '500',
    },
    attributeList: {
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        padding: 16,
        marginBottom: 24,
        gap: 12,
    },
    attributeRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 10,
    },
    attributeLabel: { fontSize: 15, color: '#334155', flex: 1 },
    attributeFilled: { color: '#166534' },
    attributeValue: { fontSize: 13, color: '#64748B', maxWidth: 160 },
    sectionTitle: {
        fontSize: 14,
        fontWeight: '600',
        color: '#64748B',
        marginBottom: 12,
        textAlign: 'center',
    },
    providerButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#1E293B',
        borderRadius: 12,
        paddingVertical: 14,
        paddingHorizontal: 20,
        marginBottom: 10,
        gap: 10,
    },
    providerButtonText: {
        color: '#FFFFFF',
        fontSize: 16,
        fontWeight: '600',
    },
    divider: {
        flexDirection: 'row',
        alignItems: 'center',
        marginVertical: 16,
        gap: 12,
    },
    dividerLine: {
        flex: 1,
        height: StyleSheet.hairlineWidth,
        backgroundColor: '#CBD5E1',
    },
    dividerText: { fontSize: 13, color: '#94A3B8' },
    manualButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        borderWidth: 1,
        borderColor: '#007AFF',
        borderRadius: 12,
        paddingVertical: 14,
        paddingHorizontal: 20,
        gap: 8,
    },
    manualButtonText: { color: '#007AFF', fontSize: 16, fontWeight: '600' },
    inputContainer: { marginBottom: 16 },
    inputLabel: { fontSize: 13, fontWeight: '600', color: '#64748B', marginBottom: 6 },
    input: {
        backgroundColor: '#FFFFFF',
        borderRadius: 10,
        paddingHorizontal: 16,
        paddingVertical: 14,
        fontSize: 16,
        color: '#1E293B',
        borderWidth: 1,
        borderColor: '#E2E8F0',
    },
    saveButton: {
        backgroundColor: '#007AFF',
        borderRadius: 12,
        paddingVertical: 14,
        alignItems: 'center',
        marginTop: 4,
    },
    saveButtonDisabled: { opacity: 0.4 },
    saveButtonText: { color: '#FFFFFF', fontSize: 16, fontWeight: '600' },
    backLink: { alignItems: 'center', paddingVertical: 16 },
    backLinkText: { fontSize: 14, color: '#007AFF' },
    readySection: {
        alignItems: 'center',
        gap: 8,
        paddingVertical: 20,
    },
    readyText: {
        fontSize: 15,
        color: '#166534',
        textAlign: 'center',
    },
    continueDisabled: { opacity: 0.4 },
    bottomActions: {
        position: 'absolute',
        bottom: 0,
        left: 0,
        right: 0,
        paddingHorizontal: 20,
        paddingTop: 16,
        backgroundColor: '#F8FAFB',
        borderTopWidth: StyleSheet.hairlineWidth,
        borderTopColor: 'rgba(0,0,0,0.1)',
    },
});

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
    attestationAppName: {
        fontSize: 22,
        fontWeight: '700',
        textAlign: 'center',
        marginBottom: 4
    },
    attestationOrigin: {
        fontSize: 12,
        color: '#94A3B8',
        textAlign: 'center',
        fontFamily: 'Inter',
        marginBottom: 20
    },
    detailsToggle: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 14,
        marginBottom: 8,
        borderRadius: 10,
        backgroundColor: 'rgba(0,0,0,0.04)',
        gap: 8
    },
    detailsToggleText: {
        fontSize: 14,
        fontWeight: '500',
        color: '#64748B'
    },
    detailsToggleIcon: {
        fontSize: 10,
        color: '#94A3B8'
    },
    bottomActions: {
        position: 'absolute',
        bottom: 0,
        left: 0,
        right: 0,
        paddingHorizontal: 20,
        paddingTop: 16,
        backgroundColor: '#F8FAFB',
        borderTopWidth: StyleSheet.hairlineWidth,
        borderTopColor: 'rgba(0,0,0,0.1)'
    },
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
    cancelButtonText: { fontSize: 16, color: '#8E8E93' },
    confirmContainer: {
        flex: 1,
        justifyContent: 'space-between',
        paddingTop: 80,
        paddingBottom: 48,
        paddingHorizontal: 24,
    },
    confirmContent: {
        alignItems: 'center',
    },
    confirmIcon: {
        width: 72,
        height: 72,
        borderRadius: 20,
        backgroundColor: '#007AFF',
        alignItems: 'center',
        justifyContent: 'center',
        marginBottom: 24
    },
    confirmIconText: {
        fontSize: 32,
        fontWeight: '700',
        color: '#FFFFFF'
    },
    confirmAppName: {
        fontSize: 20,
        fontWeight: '600',
        color: '#1E293B',
        textAlign: 'center',
        marginBottom: 4,
    },
    confirmDomain: {
        fontSize: 14,
        fontFamily: 'Inter',
        color: '#94A3B8',
        textAlign: 'center',
        marginBottom: 12
    },
    confirmHint: {
        fontSize: 14,
        color: '#94A3B8',
        textAlign: 'center',
        paddingHorizontal: 20
    },
    confirmActions: {
        flexDirection: 'row',
        gap: 12,
    },
    confirmDenyButton: {
        flex: 1,
        backgroundColor: '#F1F5F9',
        borderRadius: 14,
        paddingVertical: 16,
        alignItems: 'center',
    },
    confirmDenyButtonText: {
        color: '#64748B',
        fontSize: 17,
        fontWeight: '600',
    },
    confirmApproveButton: {
        flex: 1,
        backgroundColor: '#34C759',
        borderRadius: 14,
        paddingVertical: 16,
        alignItems: 'center',
    },
    confirmApproveButtonText: {
        color: '#FFFFFF',
        fontSize: 17,
        fontWeight: '600',
    },
    confirmButton: {
        backgroundColor: '#34C759',
        borderRadius: 14,
        paddingVertical: 16,
        paddingHorizontal: 48,
        minWidth: 200,
        alignItems: 'center'
    },
    confirmButtonText: {
        color: '#FFFFFF',
        fontSize: 18,
        fontWeight: '600'
    }
});
