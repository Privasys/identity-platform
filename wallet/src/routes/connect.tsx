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

import * as Clipboard from 'expo-clipboard';
import { useRouter, useLocalSearchParams, Stack, type Href } from 'expo-router';
import { useState, useEffect, useCallback, useRef } from 'react';
import {
    StyleSheet,
    Pressable,
    ActivityIndicator,
    Modal,
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

import { buildErrorReport, REPORT_DESTINATION } from '@/utils/logs';

import { Text, View } from '@/components/Themed';
import { useExpoPushToken } from '@/hooks/useExpoPushToken';
import { getAttestationServerToken } from '@/services/app-attest';
import { verifyAttestation, inspectAttestation } from '@/services/attestation';
import { relaySessionToken } from '@/services/broker';
import { deriveAppSub, generateDid, generatePairwiseSeed, generateCanonicalDid } from '@/services/did';
import { issueEncAuthForSignIn } from '@/services/encauth';
import * as fido2 from '@/services/fido2';
import { linkProviderViaIdP, PROVIDERS } from '@/services/identity';
import { ATTRIBUTE_MAP, attributeLabel, CANONICAL_KEYS, getProfileAssurance, getProfileValue, setProfileValue } from '@/services/attributes';
import { discloseAttribute } from '@/services/kyc';
import { getAttributeValues, type ValueOption } from '@/services/value-sets';
import { getDeviceAttribute } from '@/services/device-attributes';
import { useAuthStore } from '@/stores/auth';
import { useConsentStore } from '@/stores/consent';
import { useProfileStore } from '@/stores/profile';
import { useSessionsStore } from '@/stores/sessions';
import { useSettingsStore } from '@/stores/settings';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';
import { AttestationView, type AttestationVerificationLevel } from '@/components/AttestationView';

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
        att.workload_code_hash ?? '',
        att.workload_config_merkle_root ?? '',
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
        if (value) {
            if (assuranceFor(attr, payload.attributeRequirements) === 'gov') {
                // Gov claims are presented as enclave-signed, audience-bound
                // disclosure tokens (commit-and-prove), never the raw value.
                try {
                    attrs[attr] = await discloseAttribute(payload.rpId, attr, payload.nonce ?? payload.sessionId);
                } catch (e: any) {
                    // Never fall back to the raw gov value; omit on failure.
                    console.warn(`[CONNECT] disclosure for ${attr} failed: ${e?.message}`);
                }
            } else {
                attrs[attr] = value;
            }
        } else if (ATTRIBUTE_MAP[attr]?.deviceSourced) {
            // Device-sourceable (e.g. locale) — read from the OS so we never have
            // to ask the user for it.
            const deviceValue = getDeviceAttribute(attr);
            if (deviceValue) attrs[attr] = deviceValue;
        }
    }

    return Object.keys(attrs).length > 0 ? attrs : undefined;
}

/**
 * Determine which requested attributes are missing from the user's profile.
 * Returns the list of attribute keys that the app wants but the profile
 * doesn't have values for. 'sub' is excluded since it's always derivable.
 * Only canonical attributes are accepted — unknown keys are ignored.
 */
// The identity attributes the wallet treats as required for sign-in. Anything
// else a relying party requests is best-effort (optional): it is seeded if a
// provider supplies it, but a missing optional attribute never blocks the
// ceremony. This stops a provider that cannot supply one attribute (e.g. Google
// has no `nickname` claim) from deadlocking the flow. Per-attribute `essential`
// signalling threaded from the IdP is the cleaner long-term mechanism (Phase 2).
const REQUIRED_ATTRIBUTE_KEYS = new Set(['email', 'name']);

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
        const needsGov = assuranceFor(attr, payload.attributeRequirements) === 'gov';
        const value = profile ? getProfileValue(profile, attr) : undefined;
        if (value) {
            // Present — but a 'gov' requirement is only satisfied by a
            // gov-assured (document-verified) value, never a provider/manual one.
            if (!needsGov || getProfileAssurance(profile!, attr) === 'gov') continue;
        } else if (ATTRIBUTE_MAP[attr]?.deviceSourced && getDeviceAttribute(attr)) {
            // Device-sourceable attributes are never "missing" if the OS can
            // supply them (e.g. locale from expo-localization).
            continue;
        }
        missing.push(attr);
    }
    return missing;
}

/** Per-attribute requirement hints from the IdP, keyed by attribute key. */
export type AttributeRequirements = Record<string, { essential: boolean; assurance: string }>;

/**
 * Whether a requested attribute blocks sign-in. Prefer the IdP's per-attribute
 * `essential` flag (threaded via `attributeRequirements`); fall back to the
 * email+name heuristic for IdPs that predate it.
 */
function isEssential(attr: string, reqs?: AttributeRequirements): boolean {
    const r = reqs?.[attr];
    if (r) return r.essential;
    return REQUIRED_ATTRIBUTE_KEYS.has(attr);
}

/**
 * Assurance level an attribute must carry. 'gov' means it can only come from an
 * enclave-backed identity verification and must never be hand-typed; 'any'
 * (the default) accepts a provider or manual value.
 */
function assuranceFor(attr: string, reqs?: AttributeRequirements): string {
    return reqs?.[attr]?.assurance ?? 'any';
}

/** Subset of missing attributes that block sign-in (the rest are optional). */
function getRequiredMissing(missing: string[], reqs?: AttributeRequirements): string[] {
    return missing.filter((k) => isEssential(k, reqs));
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

/**
 * Why we trust the current attestation.
 *
 * - `fresh-as-verified`: just round-tripped to as.privasys.org with an
 *   App Attest-bound token. Highest assurance; required on first connect
 *   to a new enclave and periodically after that.
 * - `cached-trusted`: the cert measurements match a previously-verified
 *   record in the trusted-apps store and the cache is still within TTL.
 *   We did not re-contact the attestation server.
 * - `non-enclave`: the cert carried no TEE measurements (e.g. github.com
 *   behind a Let's Encrypt cert). The wallet supports FIDO2 sign-in to
 *   non-enclave RPs; attestation simply does not apply.
 */

// Re-verification cadence for already-trusted enclaves.
//
// OPEN QUESTION (TBD): how often to re-verify a known-good enclave with
// the attestation server. Trade-off: each AS round-trip burns one App
// Attest assertion (Apple rate-limits these per device/day) and adds
// latency to the user-visible critical path; on the other hand, fresher
// AS verification narrows the window in which a compromised enclave
// could ride on a stale local trust record. Today's policy:
//
//   - First connect to an enclave  →  always full verify
//   - Subsequent connects          →  full verify if last AS check was
//                                     more than REVERIFY_TTL_MS ago, OR
//                                     with probability REVERIFY_RANDOM_P
//                                     (so we sample even within TTL).
//
// Pick a final cadence once we have telemetry on how often these land in
// the foreground sign-in path.
const REVERIFY_TTL_MS = 24 * 60 * 60 * 1000;
const REVERIFY_RANDOM_P = 0.1;

interface QRPayload {
    origin: string;
    sessionId: string;
    rpId: string;
    brokerUrl: string;
    userAgent?: string;
    requestedAttributes?: string[];
    /** Per-attribute requirement hints from the IdP, keyed by attribute key:
     *  whether each is `essential` (gates sign-in) and the `assurance` it must
     *  carry ('gov' = enclave-verified identity that cannot be self-asserted,
     *  'any' = a provider/manual value is fine). Absent on IdPs that predate the
     *  identity scope — callers then fall back to the email+name heuristic. */
    attributeRequirements?: AttributeRequirements;
    appName?: string;
    privacyPolicyUrl?: string;
    clientIP?: string;
    /** Optional, UNVERIFIED label naming an agent that brokered this request
     *  (CLI/agent device flow). When present the approval grants that agent a
     *  token that acts as the user, so we surface it prominently as a
     *  delegation warning. Never treat it as a verified identity. */
    requestedBy?: string;
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
    /** Additional enclave hosts to seal in the SAME ceremony (multi-app
     *  attestation). For each, the wallet attests + bootstraps + issues an
     *  EncAuth voucher under the one unlock, so the browser can later resume a
     *  sealed session to each without another phone touch. */
    extraAppHosts?: string[];
    /** Per-session replay nonce (base64url). When omitted we fall back to
     *  `sessionId` for the session-relay challenge binding. */
    nonce?: string;
    /** OIDC client_id of the relying party. Required for EncAuth voucher
     *  issuance: the voucher must land on the same IdP session row (sid)
     *  the issued JWT will carry, and that row is keyed by client_id. */
    clientId?: string;
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
    const [reportOpen, setReportOpen] = useState(false);
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
    // How the current attestation was established. Drives the badge in
    // AttestationView so the user can tell apart a fresh attestation-server
    // round-trip from a cache hit (and so we never silently accept either
    // when the target turned out to be a non-enclave service).
    const [verificationLevel, setVerificationLevel] = useState<AttestationVerificationLevel | null>(null);
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
            // The relying-party app the user is actually signing into is
            // `payload.rpId` (e.g. `lightpanda.apps-test.privasys.org`).
            // `payload.origin` is the FIDO2 ceremony host (the IdP at
            // `privasys.id`) — attesting it would just measure the IdP,
            // not the enclave that holds the user's data, so it is
            // explicitly NOT what we want here.
            //
            // In session-relay mode the AI app host is set on `appHost`;
            // we keep that as the attestation target because the sealed
            // CBOR transport terminates there even when `rpId` points at
            // a generic IdP scope. Without an `appHost` we fall back to
            // `rpId`.
            const attestationTarget =
                payload.mode === 'session-relay' && payload.appHost
                    ? payload.appHost
                    : payload.rpId;
            console.log(`[CONNECT] startFlow — verifying attestation for ${attestationTarget}` +
                (attestationTarget !== payload.origin ? ` (fido2 origin=${payload.origin})` : ''));
            try {
                // Step 1 — inspect the cert. inspect() does NOT contact the
                // attestation server: it does the TLS handshake and parses any
                // RA-TLS extensions out of whatever cert the target presented.
                // This is how we tell apart an enclave service (mrenclave/mrtd
                // populated) from a standard FIDO2 RP behind a public cert
                // (github.com, google.com — both legitimate targets for the
                // wallet).
                let inspectResult: AttestationResult;
                try {
                    inspectResult = await inspectAttestation(attestationTarget);
                } catch (inspectErr: any) {
                    console.error(`[CONNECT] inspect() failed for ${attestationTarget}: ${inspectErr.message}`);
                    throw new Error(
                        `Could not connect to ${attestationTarget}: ${inspectErr.message}`
                    );
                }

                const hasMeasurements = !!(inspectResult.mrenclave || inspectResult.mrtd);

                // Session-relay strictly requires verified enclave measurements:
                // the FIDO2 challenge is bound to quote_hash so the relying party
                // can prove the sealed-CBOR transport reached the attested
                // appHost. A non-attested cert (typically the gateway falling
                // back to its public LE wildcard because the wallet's RA-TLS
                // client did not advertise the `privasys-ratls/1` ALPN) leaves
                // us with nothing to bind — fail fast with a clear message.
                if (payload.mode === 'session-relay' && !hasMeasurements) {
                    console.error(
                        `[CONNECT] session-relay attestation missing — ` +
                        `target=${attestationTarget} served a non-attested cert ` +
                        `(subject=${(inspectResult as any).cert_subject ?? 'unknown'}). ` +
                        `Most likely cause: the wallet's RA-TLS client did not advertise ` +
                        `the privasys-ratls/1 ALPN, so the gateway terminated the handshake ` +
                        `with its public Let's Encrypt cert.`
                    );
                    throw new Error(
                        `${attestationTarget} did not present an attested certificate. ` +
                        `Session-relay sign-in cannot proceed without enclave measurements.`
                    );
                }

                // Step 2a — non-enclave path. Standard FIDO2 RP, no attestation
                // applies. This is a supported flow, not a fallback: the wallet
                // is meant to act as a passkey for sites like github.com too.
                if (!hasMeasurements) {
                    console.log(`[CONNECT] target ${attestationTarget} is non-enclave (no TEE measurements) — proceeding without attestation`);
                    setVerificationLevel('non-enclave');
                    const credential = getCredentialForRp(payload.rpId);
                    if (credential) {
                        setIsTrusted(true);
                        if (isFromPush && !checkUnlocked()) {
                            // Push-initiated outside grace period: show "Sign in?" confirmation
                            setStep('confirm');
                            return;
                        }
                        await doAuthenticate(payload, credential.keyAlias, credential.credentialId, credential.serverRpId);
                        return;
                    }
                    // First time — register (FIDO2 handles biometric via NativeKeys)
                    await doRegister(payload);
                    return;
                }

                // Step 2b — enclave path. Decide between cached trust and a
                // fresh attestation-server round-trip based on REVERIFY_TTL_MS
                // and REVERIFY_RANDOM_P.
                const trustKey = attestationTarget;
                const trustedApp = getApp(trustKey);
                const cachedMatch =
                    !!trustedApp &&
                    isAttestationMatch(trustKey, {
                        mrenclave: inspectResult.mrenclave,
                        mrtd: inspectResult.mrtd,
                        codeHash: inspectResult.workload_code_hash,
                        configRoot: inspectResult.workload_config_merkle_root,
                    });
                const cacheAgeMs = trustedApp ? Date.now() - trustedApp.lastVerified * 1000 : Infinity;
                const sampledForReverify = Math.random() < REVERIFY_RANDOM_P;
                const reverifyDue =
                    !cachedMatch ||
                    cacheAgeMs > REVERIFY_TTL_MS ||
                    sampledForReverify;

                let result: AttestationResult;
                let level: AttestationVerificationLevel;
                if (reverifyDue) {
                    // Full verification through the attestation server. This is
                    // mandatory on first connect to a given enclave and on
                    // periodic refresh; if it fails we hard-fail the flow.
                    try {
                        const asToken = await getAttestationServerToken();
                        const reason = !trustedApp
                            ? 'first connect'
                            : !cachedMatch
                                ? 'cert measurements changed'
                                : cacheAgeMs > REVERIFY_TTL_MS
                                    ? `cache age ${Math.round(cacheAgeMs / 60000)}m exceeds TTL`
                                    : 'random sample';
                        console.log(`[CONNECT] AS verify (${reason})`);
                        // Use whichever TEE family inspect() identified —
                        // hard-coding 'sgx' here meant TDX containers (and
                        // future SEV-SNP / NVIDIA-GPU enclaves) failed
                        // verification with "expected SGX quote, found …".
                        result = await verifyAttestation(attestationTarget, {
                            tee: inspectResult.tee_type ?? 'sgx',
                            attestation_server: 'https://as.privasys.org',
                            attestation_server_token: asToken,
                        });
                    } catch (verifyErr: any) {
                        console.error(
                            `[CONNECT] verify() failed for ${attestationTarget} — ` +
                            `refusing to proceed without verified attestation: ${verifyErr.message}`
                        );
                        throw new Error(
                            `Attestation verification unavailable for ${attestationTarget}: ${verifyErr.message}. ` +
                            `Sign-in to an enclave service requires App Attest + as.privasys.org.`
                        );
                    }
                    level = 'fresh-as-verified';
                } else {
                    console.log(
                        `[CONNECT] cached attestation trusted (last AS verify ${Math.round(cacheAgeMs / 60000)}m ago, ` +
                        `within ${REVERIFY_TTL_MS / 60000}m TTL)`
                    );
                    result = inspectResult;
                    level = 'cached-trusted';
                }

                const measurement = result.mrenclave ?? result.mrtd ?? '(none)';
                const measurementLabel = result.mrenclave ? 'mrenclave' : 'mrtd';
                console.log(`[CONNECT] attestation OK [${level}] — tee=${result.tee_type ?? 'unknown'} ${measurementLabel}=${measurement.substring(0, 16)}...`);

                setAttestation(result);
                attestationRef.current = result;
                setVerificationLevel(level);

                // After a fresh AS verify, refresh the trusted-apps record's
                // lastVerified timestamp even if we'll skip straight to FIDO2
                // below. Without this, REVERIFY_TTL_MS would force a fresh AS
                // round-trip on every connect after the TTL elapses, regardless
                // of whether the user has been actively using the app.
                if (level === 'fresh-as-verified' && cachedMatch && trustedApp) {
                    addTrustedApp({
                        ...trustedApp,
                        lastVerified: Math.floor(Date.now() / 1000),
                    });
                }

                if (cachedMatch) {
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

                // New app — show full attestation details so the user can
                // approve. The "fresh-as-verified" badge surfaced in
                // AttestationView is the user-visible signal that the
                // attestation server confirmed the quote.
                setStep('attestation');
            } catch (e: any) {
                console.error(`[CONNECT] attestation FAILED:`, e.message, e);
                setError(`Attestation verification failed: ${e.message}`);
                setStep('error');
            }
        },
        [getApp, isAttestationMatch, addTrustedApp, getCredentialForRp, checkUnlocked, gracePeriodSec]
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
    /** Defensive: ensure the value we hand to the sessions store is an
     *  epoch-ms in the future. The enclave currently returns ms, but if
     *  it ever returns 0/undefined or seconds the Home tab would show
     *  the session as already expired and silently drop it. Fall back
     *  to a 5-minute window so the user still sees the session card. */
    const sanitizeRelayExpiresAt = (raw: unknown): number => {
        const fallbackMs = Date.now() + 5 * 60 * 1000;
        if (typeof raw !== 'number' || !Number.isFinite(raw)) return fallbackMs;
        // < 1e12 means the value can't be a sane epoch-ms after Sep 2001
        // — almost certainly seconds. Treat it as such.
        const asMs = raw < 1e12 ? raw * 1000 : raw;
        if (asMs <= Date.now() + 1000) return fallbackMs;
        return asMs;
    };

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

    /** Fire-and-forget EncAuth voucher issuance after a successful
     *  session-relay sign-in (Phase C wiring). The voucher lets the
     *  browser silently re-bootstrap its sealed session (idle TTL,
     *  reload) without waking this wallet. Failures only mean the
     *  browser falls back to a full wallet ceremony on the next rebind,
     *  so they are logged and swallowed — never block the sign-in. */
    const maybeIssueEncAuth = (
        payload: QRPayload,
        keyAlias: string,
        result: { sessionToken: string; userId?: string; sessionRelay?: fido2.SessionRelayBinding },
        relayArg: { quoteHash: string } | undefined,
    ) => {
        if (!result.sessionRelay || !relayArg) return;
        if (!payload.clientId) {
            console.log('[CONNECT] payload has no clientId — skipping EncAuth voucher (silent rebind disabled)');
            return;
        }
        if (!result.userId || !result.sessionToken) {
            console.log('[CONNECT] missing userId/sessionToken — skipping EncAuth voucher');
            return;
        }
        const att = attestationRef.current ?? attestation;
        if (!att) return;
        void issueEncAuthForSignIn({
            walletSessionToken: result.sessionToken,
            keyId: keyAlias,
            clientId: payload.clientId,
            sub: result.userId,
            encPubB64: result.sessionRelay.encPub,
            quoteHashHex: relayArg.quoteHash,
            attestation: att,
            host: payload.appHost,
        }).then(
            ({ sid }) => console.log(`[CONNECT] EncAuth voucher uploaded (sid=${sid.substring(0, 8)}…)`),
            (err) => console.warn('[CONNECT] EncAuth voucher upload failed (silent rebind disabled):', err),
        );
    };

    /** Full attestation (inspect + attestation-server verify) of an additional
     *  enclave host. Always verifies through as.privasys.org — extra hosts are
     *  attested once per ceremony, so we never trust a cache for them. Throws on
     *  an invalid/unreachable enclave so the caller can skip just that host. */
    const attestExtraHost = async (host: string): Promise<AttestationResult> => {
        const inspected = await inspectAttestation(host);
        const asToken = await getAttestationServerToken();
        const verified = await verifyAttestation(host, {
            tee: inspected.tee_type ?? 'sgx',
            attestation_server: 'https://as.privasys.org',
            attestation_server_token: asToken,
        });
        if (!verified.valid) throw new Error(`attestation did not verify for ${host}`);
        // Merge: inspect carries the rich OID-derived fields the voucher hashes,
        // verify carries the authoritative measurements/validity.
        return { ...inspected, ...verified };
    };

    /** Multi-app attestation: for every host in `extraAppHosts`, attest +
     *  bootstrap + issue an EncAuth voucher, so one ceremony seals the session
     *  to several enclaves. Runs back-to-back right after the primary voucher so
     *  the keystore's biometric grace window covers every signature in one
     *  unlock. Per-host failures are swallowed — the primary sign-in already
     *  succeeded; an unsealed extra host just falls back to a ceremony next time. */
    const issueExtraAppVouchers = async (
        payload: QRPayload,
        keyAlias: string,
        result: { sessionToken: string; userId?: string },
    ) => {
        const hosts = (payload.extraAppHosts ?? []).filter((h) => h && h !== payload.appHost);
        if (
            hosts.length === 0 ||
            payload.mode !== 'session-relay' ||
            !payload.sdkPub ||
            !payload.clientId ||
            !result.userId ||
            !result.sessionToken
        ) {
            return;
        }
        for (const host of hosts) {
            try {
                const att = await attestExtraHost(host);
                const bs = await fido2.bootstrapHost(host, payload.sdkPub);
                await issueEncAuthForSignIn({
                    walletSessionToken: result.sessionToken,
                    keyId: keyAlias,
                    clientId: payload.clientId,
                    sub: result.userId,
                    encPubB64: bs.encPub,
                    quoteHashHex: deriveQuoteHash(att),
                    attestation: att,
                    host,
                });
                addTrustedApp({
                    rpId: host,
                    origin: host,
                    appName: payload.appName,
                    mrenclave: att.mrenclave,
                    mrtd: att.mrtd,
                    codeHash: att.workload_code_hash,
                    configRoot: att.workload_config_merkle_root,
                    teeType: att.tee_type || 'sgx',
                    lastVerified: Math.floor(Date.now() / 1000),
                    credentialId: '', // voucher-only trust row (no passkey on this host)
                });
                console.log(`[CONNECT] extra-app voucher issued for ${host}`);
            } catch (err: any) {
                console.warn(`[CONNECT] extra-app voucher for ${host} failed:`, err?.message ?? err);
            }
        }
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
                const safeExpiresAt = sanitizeRelayExpiresAt(result.sessionRelay.expiresAt);
                console.log(
                    `[CONNECT] registering relay session on Home: sessionId=${result.sessionRelay.sessionId.substring(0, 8)}... rawExpiresAt=${result.sessionRelay.expiresAt} safeExpiresAt=${safeExpiresAt} (in ${Math.round((safeExpiresAt - Date.now()) / 1000)}s)`
                );
                addRelaySession({
                    sessionId: result.sessionRelay.sessionId,
                    rpId: payload.rpId,
                    origin: payload.origin,
                    appName: payload.appName,
                    expiresAt: safeExpiresAt,
                    startedAt: Date.now(),
                });
            } else {
                console.warn('[CONNECT] registration result has no sessionRelay binding — Home tab will not show this session');
            }

            // Upload the silent-rebind voucher while the keystore's
            // biometric grace (where supported) still covers the extra
            // hardware signature.
            maybeIssueEncAuth(payload, keyAlias, result, sessionRelayArg);
            // Multi-app attestation: seal any extra enclave hosts in the same
            // ceremony (back-to-back, under the one biometric grace window).
            void issueExtraAppVouchers(payload, keyAlias, result);

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

            // Refresh the trusted-app row so the Home tab reflects the
            // most-recent sign-in. Look the row up under the same key
            // we attested in `startFlow` (appHost in session-relay
            // mode, otherwise rpId) — `payload.rpId` alone would miss
            // the row in session-relay flows where rpId is the IdP
            // (`privasys.id`) and the trust row lives under the AI
            // enclave appHost. Federated rpIds reuse a single row, so
            // we also overwrite `appName` with the friendliest label
            // currently in flight — without this the row stays frozen
            // on whatever the very first sign-in surfaced.
            const trustKey =
                payload.mode === 'session-relay' && payload.appHost
                    ? payload.appHost
                    : payload.rpId;
            const existingTrust = getApp(trustKey);
            if (existingTrust) {
                addTrustedApp({
                    ...existingTrust,
                    appName: payload.appName ?? existingTrust.appName,
                    lastVerified: Math.floor(Date.now() / 1000),
                });
            }

            // Phase E: when the SDK opted into the sealed session-relay
            // bootstrap, surface the live session on the Home screen
            // until the enclave-side binding expires.
            if (result.sessionRelay) {
                const safeExpiresAt = sanitizeRelayExpiresAt(result.sessionRelay.expiresAt);
                console.log(
                    `[CONNECT] registering relay session on Home: sessionId=${result.sessionRelay.sessionId.substring(0, 8)}... rawExpiresAt=${result.sessionRelay.expiresAt} safeExpiresAt=${safeExpiresAt} (in ${Math.round((safeExpiresAt - Date.now()) / 1000)}s)`
                );
                addRelaySession({
                    sessionId: result.sessionRelay.sessionId,
                    // Key the relay session by the same identity as the
                    // trusted-app row (appHost in session-relay mode,
                    // otherwise rpId). Without this, the Home tab
                    // shows two separate cards for the same app — a
                    // sealed "Relaying…" tile keyed by the IdP rpId
                    // and a duplicate trusted-app tile keyed by the
                    // enclave appHost.
                    rpId: trustKey,
                    origin: payload.origin,
                    appName: payload.appName,
                    expiresAt: safeExpiresAt,
                    startedAt: Date.now(),
                });
            }

            // Upload the silent-rebind voucher while the keystore's
            // biometric grace (where supported) still covers the extra
            // hardware signature.
            maybeIssueEncAuth(payload, keyAlias, result, sessionRelayArg);
            // Multi-app attestation: seal any extra enclave hosts in the same
            // ceremony (back-to-back, under the one biometric grace window).
            void issueExtraAppVouchers(payload, keyAlias, result);

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

        // Store the trust record under the entity that was actually
        // attested in `startFlow` — appHost in session-relay mode,
        // otherwise rpId. `payload.origin` is the FIDO2 ceremony host
        // (the IdP at privasys.id) and is shared across every adopter,
        // so keying the trust row on it would conflate every relying
        // party into a single row that always shows the IdP's
        // measurements (i.e. none — privasys.id is not an enclave) and
        // overwrite the per-RP enclave data we just verified.
        const trustKey =
            payload.mode === 'session-relay' && payload.appHost
                ? payload.appHost
                : payload.rpId;

        if (attestation) {
            addTrustedApp({
                rpId: trustKey,
                origin: trustKey,
                appName: payload.appName,
                mrenclave: attestation.mrenclave,
                mrtd: attestation.mrtd,
                codeHash: attestation.workload_code_hash,
                configRoot: attestation.workload_config_merkle_root,
                teeType: attestation.tee_type || 'sgx',
                lastVerified: Math.floor(Date.now() / 1000),
                credentialId,
            });
        } else {
            addTrustedApp({
                rpId: trustKey,
                origin: trustKey,
                appName: payload.appName,
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

        // Re-check: are any *essential* attributes still missing? Optional ones
        // (per the IdP's attributeRequirements, or the email+name fallback) never block.
        const updatedProfile = useProfileStore.getState().profile;
        const requiredMissing = getRequiredMissing(
            getMissingAttributes(pending.payload, updatedProfile),
            pending.payload.attributeRequirements,
        );
        if (requiredMissing.length > 0) {
            Alert.alert(
                'Missing information',
                `Please provide: ${requiredMissing.map((k) => attributeLabel(k)).join(', ')}`,
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
                            {qr.requestedBy && (
                                <View style={styles.confirmAgentBanner}>
                                    <Text style={styles.confirmAgentText}>
                                        Requested by “{qr.requestedBy}”. Approving lets it act as you until you revoke it in Settings.
                                    </Text>
                                </View>
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
                        displayName={appName(qr.rpId)}
                        isChanged={false}
                        verificationLevel={verificationLevel}
                        onApprove={handleApprove}
                        onReject={handleReject}
                    />
                )}

                {step === 'attestation-changed' && attestation && qr && (
                    <AttestationView
                        attestation={attestation}
                        rpId={qr.rpId}
                        displayName={appName(qr.rpId)}
                        isChanged={true}
                        verificationLevel={verificationLevel}
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
                        attributeRequirements={qr.attributeRequirements}
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
                        <Pressable
                            style={styles.reportLink}
                            onPress={() => setReportOpen(true)}
                            hitSlop={8}
                        >
                            <Text style={styles.reportLinkText}>Report Error</Text>
                        </Pressable>
                    </View>
                )}

                <ReportErrorModal
                    visible={reportOpen}
                    errorMessage={error}
                    onClose={() => setReportOpen(false)}
                />
            </View>
        </>
    );
}

// ── Report Error preview modal ──────────────────────────────────────────

/**
 * Shows the user exactly what will be sent and to whom before they hand
 * the report off. We do not auto-submit anything yet — the destination
 * (errors.privasys.org) will become a real ingestion endpoint once the
 * companion API is ready. For now the user copies the text and pastes
 * it into the conversation, email, or issue tracker themselves.
 */
function ReportErrorModal({
    visible,
    errorMessage,
    onClose,
}: {
    visible: boolean;
    errorMessage: string | null;
    onClose: () => void;
}) {
    const insets = useSafeAreaInsets();
    const report = visible ? buildErrorReport(errorMessage) : '';

    const onCopy = async () => {
        await Clipboard.setStringAsync(report);
        Alert.alert(
            'Copied',
            `Report copied to the clipboard. Paste it into your message to ${REPORT_DESTINATION} or share it with support.`,
            [{ text: 'OK', onPress: onClose }],
        );
    };

    return (
        <Modal visible={visible} animationType="slide" onRequestClose={onClose} transparent={false}>
            <RNView style={[reportStyles.screen, { paddingTop: insets.top + 12 }]}>
                <RNView style={reportStyles.header}>
                    <Pressable onPress={onClose} hitSlop={10}>
                        <Ionicons name="close" size={24} color="#0F172A" />
                    </Pressable>
                    <Text style={reportStyles.headerTitle}>Report Error</Text>
                    <RNView style={{ width: 24 }} />
                </RNView>

                <RNView style={reportStyles.destinationCard}>
                    <Text style={reportStyles.destinationLabel}>Will be sent to</Text>
                    <Text style={reportStyles.destinationValue}>{REPORT_DESTINATION}</Text>
                    <Text style={reportStyles.destinationNote}>
                        Automatic submission is not wired up yet — for now, copy the report below
                        and share it with the Privasys team.
                    </Text>
                </RNView>

                <Text style={reportStyles.previewLabel}>Report contents</Text>
                <ScrollView style={reportStyles.previewScroll} contentContainerStyle={{ padding: 12 }}>
                    <Text style={reportStyles.previewText} selectable>
                        {report}
                    </Text>
                </ScrollView>

                <RNView style={[reportStyles.actions, { paddingBottom: insets.bottom + 16 }]}>
                    <Pressable style={reportStyles.cancelButton} onPress={onClose}>
                        <Text style={reportStyles.cancelButtonText}>Cancel</Text>
                    </Pressable>
                    <Pressable style={reportStyles.copyButton} onPress={onCopy}>
                        <Ionicons name="copy-outline" size={16} color="#FFFFFF" />
                        <Text style={reportStyles.copyButtonText}>Copy Report</Text>
                    </Pressable>
                </RNView>
            </RNView>
        </Modal>
    );
}

const reportStyles = StyleSheet.create({
    screen: { flex: 1, backgroundColor: '#F8FAFB' },
    header: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingHorizontal: 20,
        paddingBottom: 16,
    },
    headerTitle: { fontSize: 18, fontWeight: '700', color: '#0F172A' },
    destinationCard: {
        backgroundColor: '#FFFFFF',
        marginHorizontal: 20,
        borderRadius: 12,
        padding: 16,
        marginBottom: 16,
    },
    destinationLabel: { fontSize: 12, color: '#64748B', marginBottom: 4 },
    destinationValue: { fontSize: 16, fontWeight: '600', color: '#0F172A', marginBottom: 8 },
    destinationNote: { fontSize: 12, color: '#64748B', lineHeight: 18 },
    previewLabel: {
        fontSize: 13,
        fontWeight: '600',
        color: '#64748B',
        paddingHorizontal: 20,
        marginBottom: 6,
    },
    previewScroll: {
        flex: 1,
        marginHorizontal: 20,
        backgroundColor: '#FFFFFF',
        borderRadius: 12,
        borderWidth: 1,
        borderColor: '#E2E8F0',
    },
    previewText: { fontSize: 11, fontFamily: 'SpaceMono', color: '#0F172A', lineHeight: 16 },
    actions: {
        flexDirection: 'row',
        gap: 12,
        paddingHorizontal: 20,
        paddingTop: 16,
    },
    cancelButton: {
        flex: 1,
        paddingVertical: 14,
        borderRadius: 12,
        backgroundColor: '#FFFFFF',
        borderWidth: 1,
        borderColor: '#E2E8F0',
        alignItems: 'center',
    },
    cancelButtonText: { fontSize: 15, fontWeight: '600', color: '#0F172A' },
    copyButton: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        paddingVertical: 14,
        borderRadius: 12,
        backgroundColor: '#007AFF',
    },
    copyButtonText: { fontSize: 15, fontWeight: '600', color: '#FFFFFF' },
});

// ── Attestation detail view ─────────────────────────────────────────────

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
    attributeRequirements,
    attestation,
    onComplete,
    onCancel,
}: {
    rpId: string;
    appName?: string;
    privacyPolicyUrl?: string;
    missingAttributes: string[];
    attributeRequirements?: AttributeRequirements;
    attestation: AttestationResult | null;
    onComplete: () => void;
    onCancel: () => void;
}) {
    const insets = useSafeAreaInsets();
    const { updateProfile, setAttribute, createProfile } = useProfileStore();
    const profile = useProfileStore((s) => s.profile);

    const router = useRouter();
    const [mode, setMode] = useState<'choose' | 'manual'>('choose');
    const [linkingProvider, setLinkingProvider] = useState<string | null>(null);
    const [manualValues, setManualValues] = useState<Record<string, string>>({});
    const [localePickerOpen, setLocalePickerOpen] = useState(false);
    const [localeOptions, setLocaleOptions] = useState<ValueOption[]>([]);
    const profileCreated = useRef(false);

    // Lazily fetch the locale value set (from the IdP referential) when manual
    // entry needs it, so the wallet doesn't bundle its own copy.
    useEffect(() => {
        if (mode === 'manual' && localeOptions.length === 0) {
            getAttributeValues('locale').then(setLocaleOptions).catch(() => {});
        }
    }, [mode, localeOptions.length]);

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
                    locale: getDeviceAttribute('locale'),
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

    // Check if all missing attributes are now present in the profile (a 'gov'
    // requirement is only met by a gov-assured value, not a provider/manual one).
    const stillMissing = missingAttributes.filter((attr) => {
        if (!profile || !getProfileValue(profile, attr)) return true;
        if (assuranceFor(attr, attributeRequirements) === 'gov') {
            return getProfileAssurance(profile, attr) !== 'gov';
        }
        return false;
    });
    // Essential attributes (per the IdP's attributeRequirements, or the
    // email+name fallback) block Continue; the rest are optional.
    const requiredMissing = getRequiredMissing(stillMissing, attributeRequirements);
    // A gov-assurance claim can only be satisfied by an enclave identity
    // verification — surface a "Verify with your ID" path when one is missing.
    const hasGovMissing = stillMissing.some(
        (attr) => assuranceFor(attr, attributeRequirements) === 'gov',
    );

    // Launch the KYC capture flow (NFC chip read + selfie → verifier enclave →
    // gov-assurance auto-fill). On return, the profile is updated and the gating
    // below recomputes, satisfying the gov claim.
    const handleVerifyIdentity = () => {
        // Cast: the typed-routes union regenerates at build time (the route file
        // is new); the path resolves correctly at runtime.
        router.push('/kyc-capture' as Href);
    };

    const handleLinkProvider = async (providerKey: string) => {
        setLinkingProvider(providerKey);
        try {
            const result = await linkProviderViaIdP(providerKey);

            // Update profile with normalised provider data
            const store = useProfileStore.getState();
            store.linkProvider(result.provider);

            for (const attr of result.seedAttributes) {
                // Only seed if the profile doesn't already have this value.
                const existing = profile ? getProfileValue(profile, attr.key) : undefined;
                if (!existing) {
                    setProfileValue(store, attr.key, attr.value, 'provider', {
                        sourceProvider: attr.sourceProvider ?? providerKey,
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
    // Save is enabled once the essential, typeable fields are filled. Optional
    // fields may be left blank; gov-assurance fields are never hand-typed (they
    // come from ID verification) so they don't gate the manual Save either.
    const manualRequiredFilled = missingAttributes
        .filter((attr) => isEssential(attr, attributeRequirements)
            && assuranceFor(attr, attributeRequirements) !== 'gov')
        .every((attr) => manualValues[attr]?.trim());

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
            codeHash: attestation?.workload_code_hash ?? '',
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
                            const govVerified = assuranceFor(attr, attributeRequirements) === 'gov';
                            const isOptional = !isEssential(attr, attributeRequirements);
                            const suffix = govVerified ? ' (verified ID)' : isOptional ? ' (optional)' : '';
                            return (
                                <RNView key={attr} style={acqStyles.attributeRow}>
                                    <Ionicons
                                        name={isFilled ? 'checkmark-circle' : govVerified ? 'shield-checkmark-outline' : 'ellipse-outline'}
                                        size={20}
                                        color={isFilled ? '#34C759' : govVerified ? '#F59E0B' : '#94A3B8'}
                                    />
                                    <Text style={[acqStyles.attributeLabel, isFilled && acqStyles.attributeFilled]}>
                                        {attributeLabel(attr)}{suffix}
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

                    {requiredMissing.length === 0 ? (
                        /* Required attributes present — optional ones don't block */
                        <RNView style={acqStyles.readySection}>
                            <Ionicons name="checkmark-circle" size={32} color="#34C759" />
                            <Text style={acqStyles.readyText}>All set! Tap continue to finish signing in.</Text>
                        </RNView>
                    ) : mode === 'choose' ? (
                        /* Provider linking options */
                        <>
                            {hasGovMissing && (
                                <>
                                    <Pressable
                                        style={acqStyles.providerButton}
                                        onPress={handleVerifyIdentity}
                                        disabled={linkingProvider !== null}
                                    >
                                        <Ionicons name="shield-checkmark-outline" size={20} color="#FFFFFF" />
                                        <Text style={acqStyles.providerButtonText}>Verify with your ID</Text>
                                    </Pressable>
                                    <RNView style={acqStyles.privacyNotice}>
                                        <Ionicons name="lock-closed-outline" size={16} color="#F59E0B" />
                                        <Text style={acqStyles.privacyNoticeText}>
                                            A government-verified attribute is required. Your ID is checked in a
                                            secure enclave; the value stays on your device.
                                        </Text>
                                    </RNView>
                                    <RNView style={acqStyles.divider}>
                                        <RNView style={acqStyles.dividerLine} />
                                        <Text style={acqStyles.dividerText}>or</Text>
                                        <RNView style={acqStyles.dividerLine} />
                                    </RNView>
                                </>
                            )}
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
                                // Gov-assurance attributes (birthdate, nationality,
                                // age_over_*) are produced only by an enclave-backed
                                // identity verification — never hand-typed. The NFC +
                                // biometric capture flow (Phase 2) fills these; until it
                                // ships, surface the requirement instead of a text box.
                                if (assuranceFor(attr, attributeRequirements) === 'gov') {
                                    return (
                                        <RNView key={attr} style={acqStyles.inputContainer}>
                                            <Text style={acqStyles.inputLabel}>{label}</Text>
                                            <RNView style={acqStyles.privacyNotice}>
                                                <Ionicons name="shield-checkmark-outline" size={16} color="#F59E0B" />
                                                <Text style={acqStyles.privacyNoticeText}>
                                                    Filled by verifying your ID document — not typed.
                                                </Text>
                                            </RNView>
                                        </RNView>
                                    );
                                }
                                // locale must be a standard BCP-47 tag — offer a
                                // constrained picker instead of free text.
                                if (attr === 'locale') {
                                    const selected = manualValues.locale;
                                    return (
                                        <RNView key={attr} style={acqStyles.inputContainer}>
                                            <Text style={acqStyles.inputLabel}>{label}</Text>
                                            <Pressable
                                                style={acqStyles.input}
                                                onPress={() => setLocalePickerOpen(true)}
                                            >
                                                <Text style={selected ? acqStyles.pickerValue : acqStyles.pickerPlaceholder}>
                                                    {selected
                                                        ? (localeOptions.find((o) => o.value === selected)?.label ?? selected)
                                                        : 'Select a language'}
                                                </Text>
                                            </Pressable>
                                        </RNView>
                                    );
                                }
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
                                style={[acqStyles.saveButton, !manualRequiredFilled && acqStyles.saveButtonDisabled]}
                                onPress={handleManualSave}
                                disabled={!manualRequiredFilled}
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

                {/* Locale picker modal (BCP-47 tags) */}
                <Modal
                    visible={localePickerOpen}
                    animationType="slide"
                    transparent
                    onRequestClose={() => setLocalePickerOpen(false)}
                >
                    <Pressable style={acqStyles.pickerBackdrop} onPress={() => setLocalePickerOpen(false)}>
                        <RNView style={acqStyles.pickerSheet}>
                            <Text style={acqStyles.pickerTitle}>Select a language</Text>
                            <ScrollView>
                                {localeOptions.map((opt) => (
                                    <Pressable
                                        key={opt.value}
                                        style={acqStyles.pickerRow}
                                        onPress={() => {
                                            setManualValues((prev) => ({ ...prev, locale: opt.value }));
                                            setLocalePickerOpen(false);
                                        }}
                                    >
                                        <Text style={acqStyles.pickerRowText}>{opt.label}</Text>
                                        {manualValues.locale === opt.value && (
                                            <Ionicons name="checkmark" size={20} color="#007AFF" />
                                        )}
                                    </Pressable>
                                ))}
                            </ScrollView>
                        </RNView>
                    </Pressable>
                </Modal>

                {/* Bottom action buttons */}
                <RNView style={[acqStyles.bottomActions, { paddingBottom: Math.max(insets.bottom, 20) }]}>
                    <RNView style={styles.buttonRow}>
                        <Pressable style={styles.rejectButton} onPress={onCancel}>
                            <Text style={styles.rejectButtonText}>Cancel</Text>
                        </Pressable>
                        <Pressable
                            style={[styles.approveButton, requiredMissing.length > 0 && acqStyles.continueDisabled]}
                            onPress={handleContinue}
                            disabled={requiredMissing.length > 0}
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
    pickerValue: { fontSize: 16, color: '#0F172A' },
    pickerPlaceholder: { fontSize: 16, color: '#94A3B8' },
    pickerBackdrop: { flex: 1, justifyContent: 'flex-end', backgroundColor: 'rgba(0,0,0,0.4)' },
    pickerSheet: { backgroundColor: '#FFFFFF', borderTopLeftRadius: 16, borderTopRightRadius: 16, paddingTop: 16, paddingBottom: 32, maxHeight: '70%' },
    pickerTitle: { fontSize: 16, fontWeight: '600', textAlign: 'center', marginBottom: 12, color: '#0F172A' },
    pickerRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingVertical: 14, paddingHorizontal: 24, borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: '#E2E8F0' },
    pickerRowText: { fontSize: 16, color: '#0F172A' },
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
    verifyBadge: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingHorizontal: 12,
        paddingVertical: 8,
        borderRadius: 8,
        marginBottom: 12,
        gap: 8,
    },
    verifyBadgeFresh: { backgroundColor: '#E8FFF0', borderWidth: 1, borderColor: '#34D399' },
    verifyBadgeCached: { backgroundColor: '#F1F5F9', borderWidth: 1, borderColor: '#CBD5E1' },
    verifyBadgeIcon: { fontSize: 14, fontWeight: '700', color: '#0F766E' },
    verifyBadgeText: { fontSize: 13, fontWeight: '500', color: '#0F172A', flex: 1 },
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
    reportLink: {
        marginTop: 20,
        paddingVertical: 8,
        paddingHorizontal: 12,
        alignItems: 'center'
    },
    reportLinkText: { color: '#007AFF', fontSize: 15, fontWeight: '500' },
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
    confirmAgentBanner: {
        marginTop: 16,
        marginHorizontal: 12,
        paddingVertical: 10,
        paddingHorizontal: 14,
        borderRadius: 10,
        backgroundColor: 'rgba(234, 179, 8, 0.12)',
        borderWidth: 1,
        borderColor: 'rgba(234, 179, 8, 0.4)'
    },
    confirmAgentText: {
        fontSize: 13,
        fontFamily: 'Inter',
        color: '#EAB308',
        textAlign: 'center'
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
