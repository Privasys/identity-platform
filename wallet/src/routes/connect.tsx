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

import { CameraView, useCameraPermissions } from 'expo-camera';
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

import { base64urlToBytes } from '@/utils/encoding';
import { buildErrorReport, REPORT_DESTINATION } from '@/utils/logs';

import { DataRequestConsent } from '@/components/DataRequestConsent';
import { Text, View } from '@/components/Themed';
import { useExpoPushToken } from '@/hooks/useExpoPushToken';
import { getAttestationServerToken } from '@/services/app-attest';
import { inspectAttestation, attestEnclave } from '@/services/attestation';
import { diffTrustedAttestation, type AttestationDiff } from '@/services/attestation-diff';
import { ensureDrive } from '@/services/drive';
import { appIdFromOids } from '@/services/release-provenance';
import { relaySessionToken } from '@/services/broker';
import { registerPushTokenWithIdp } from '@/services/vault-approval-api';
import { deriveAppSub, generateDid, generatePairwiseSeed, generateCanonicalDid } from '@/services/did';
import { issueEncAuthForSignIn } from '@/services/encauth';
import * as fido2 from '@/services/fido2';
import { linkProviderViaIdP, PROVIDERS } from '@/services/identity';
import { ATTRIBUTE_MAP, attributeLabel, CANONICAL_KEYS, getProfileAssurance, getProfileValue, setProfileValue } from '@/services/attributes';
import { discloseAttribute, provePresence, voucherForAttribute } from '@/services/kyc';
import { getAttributeValues, type ValueOption } from '@/services/value-sets';
import { getDeviceAttribute } from '@/services/device-attributes';
import { useAuthStore } from '@/stores/auth';
import { useConsentStore } from '@/stores/consent';
import { useProfileStore } from '@/stores/profile';
import {
    serviceKeyFor,
    useServiceSessionsStore,
    type AttestationTrace,
    type SessionTrace,
    type SharedAttributeTrace,
} from '@/stores/service-sessions';
import { useSessionsStore } from '@/stores/sessions';
import { useSettingsStore } from '@/stores/settings';
import { useTrustedAppsStore } from '@/stores/trusted-apps';

import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';
import { AttestationView, type AttestationVerificationLevel, type VerificationState } from '@/components/AttestationView';

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
/** Ceremonial presence attribute: proven by a fresh in-flow selfie matched to
 *  the document portrait inside the enclave — never a stored profile value. */
const PRESENCE_KEY = 'holder_present';

async function resolveRequestedAttributes(
    payload: QRPayload,
    profile: import('@/stores/profile').UserProfile | null,
    approved?: Set<string> | null,
    selfieBase64?: string | null,
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
        // Consent gate: only attributes the user approved on the consent
        // screen (or via standing consent) leave the wallet. `sub` is exempt —
        // it IS the sign-in.
        if (approved && !approved.has(attr)) continue;
        if (attr === PRESENCE_KEY) {
            // Fresh-presence ceremony: the selfie captured in THIS flow is
            // matched in-enclave against the committed document portrait.
            // No selfie (user skipped) → attribute omitted; the relying party
            // applies its own policy to the absence.
            //
            // NB since verifier v0.6.0 a FAILED live check (e.g. wrong face)
            // is NOT an exception — it returns HTTP 200 with a SIGNED failure
            // receipt (value:false, failure.retryable). So the token below may
            // be an affirmation OR a charged failure receipt; either way it is
            // the truthful, RP-auditable result and is delivered as-is. The
            // caller inspects it via presenceOutcome() to drive honest wallet
            // UX. The catch now only covers a transport/enclave error (the
            // ceremony did not run) — then presence is genuinely omitted.
            if (!selfieBase64) continue;
            try {
                attrs[attr] = await provePresence(
                    payload.rpId,
                    selfieBase64,
                    payload.nonce ?? payload.sessionId,
                    voucherForAttribute(PRESENCE_KEY, payload.disclosureVouchers),
                );
            } catch (e: any) {
                // The ceremony could not run (transport/enclave error) — never
                // fake presence; omit and let the RP see the absence.
                console.warn(`[CONNECT] presence proof failed to run: ${e?.message}`);
            }
            continue;
        }
        const value = getProfileValue(profile, attr);
        if (value) {
            if (assuranceFor(attr, payload.attributeRequirements) === 'gov') {
                // Gov claims are presented as enclave-signed, audience-bound
                // disclosure tokens (commit-and-prove), never the raw value.
                try {
                    attrs[attr] = await discloseAttribute(payload.rpId, attr, payload.nonce ?? payload.sessionId, payload.disclosureVouchers);
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

/** Outcome of a fresh-presence ceremony, for honest wallet UX.
 *  - null: presence was not part of this sign-in (or the user skipped it).
 *  - 'affirmed': the enclave confirmed the document holder is present.
 *  - 'failed-retryable': the live check did not pass, but a fresh attempt could
 *    succeed (e.g. a poor selfie capture) — the RP was charged.
 *  - 'failed-final': the check did not pass and retrying will not help, OR the
 *    ceremony could not run (transport/enclave error). */
type PresenceOutcome = null | 'affirmed' | 'failed-retryable' | 'failed-final';

/** Decode an SD-JWT VC disclosure (`<jws>~`) payload — value + failure block —
 *  WITHOUT verifying the signature. The relying party re-verifies the VC; the
 *  wallet only needs the shape to show the user a truthful result. */
function decodeDisclosurePayload(
    token: string,
): { value: unknown; failure?: { retryable?: boolean } } | null {
    const parts = token.replace(/~$/, '').split('.');
    if (parts.length < 2) return null;
    try {
        const json = new TextDecoder().decode(base64urlToBytes(parts[1]));
        const p = JSON.parse(json);
        return { value: p.value, failure: p.failure };
    } catch {
        return null;
    }
}

/** Classify the presence result from the resolved attributes, so the flow can
 *  show success vs a truthful "couldn't confirm it's you" instead of an
 *  unconditional green screen (verifier v0.6.0 returns a signed failure receipt
 *  rather than an error, so a failed check now arrives as a delivered token). */
function presenceOutcome(
    payload: QRPayload,
    attributes: Record<string, string> | undefined,
    selfieProvided: boolean,
): PresenceOutcome {
    if (!(payload.requestedAttributes ?? []).includes(PRESENCE_KEY)) return null;
    const token = attributes?.[PRESENCE_KEY];
    if (!token) {
        // No presence token delivered: either the user skipped the selfie
        // (conscious, not a failure) or the ceremony could not run at all.
        return selfieProvided ? 'failed-final' : null;
    }
    const d = decodeDisclosurePayload(token);
    if (!d) return null;
    if (d.value === true && !d.failure) return 'affirmed';
    return d.failure?.retryable ? 'failed-retryable' : 'failed-final';
}

/**
 * Patch resolved attributes onto the IdP auth code (POST /session/complete).
 * The SDK's frame-host does this in the iframe flow; in the device flow the
 * wallet is the only party that can. IdP-brokered payloads only (clientId
 * set, origin = the IdP); best-effort — the sign-in itself already succeeded.
 */
async function patchSessionAttributes(
    payload: QRPayload,
    attributes: Record<string, string> | undefined,
): Promise<void> {
    if (!payload.clientId || !attributes || Object.keys(attributes).length === 0) return;
    if (!payload.origin?.includes('privasys.id')) return;
    try {
        await fetch(`https://${payload.origin}/session/complete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: payload.sessionId, attributes }),
        });
    } catch (e: any) {
        console.warn('[CONNECT] session attribute patch failed:', e?.message);
    }
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

/** One row on the sign-in consent screen. */
interface SignInConsentItem {
    key: string;
    label: string;
    /** The relying party requires it to complete sign-in (locked on). */
    essential: boolean;
    /** Gov-assurance: shared as an enclave-signed, paid disclosure token. */
    gov: boolean;
    /** Whether the wallet can supply it right now (profile or device value). */
    hasValue: boolean;
}

/** Stable per-relying-party consent key. `rpId` is the shared FIDO2 RP
 *  (privasys.id) for every IdP-brokered client, so consent must key on the
 *  client identity; older IdPs omit clientId → fall back to appName@rpId. */
function consentKeyFor(payload: QRPayload): string {
    return payload.clientId || `${payload.appName ?? ''}@${payload.rpId}`;
}

/** Snapshot of one verified enclave attestation for the session trace. */
function attestationTraceFrom(host: string, att: AttestationResult): AttestationTrace {
    return {
        host,
        teeType:
            att.tee_type === 'sgx' || att.tee_type === 'tdx' ||
            att.tee_type === 'sev-snp' || att.tee_type === 'nvidia-gpu'
                ? att.tee_type
                : 'none',
        mrenclave: att.mrenclave,
        mrtd: att.mrtd,
        codeHash: att.workload_code_hash,
        configRoot: att.workload_config_merkle_root,
        imageRef: att.workload_image_ref,
        quoteStatus: att.quote_verification_status,
        appId: appIdFromOids(att.custom_oids),
        verifiedAt: Date.now(),
    };
}

/** Record one completed authentication ceremony as a per-app session trace
 *  (the audit trail Home + Service Details render). Returns the trace id so
 *  multi-app ceremonies can attach companion-enclave attestations. */
function recordCeremonyTrace(
    payload: QRPayload,
    opts: {
        channel: 'qr' | 'push';
        attestation?: AttestationResult | null;
        /** Attribute values as actually sent (gov attrs are disclosure tokens). */
        sharedValues?: Record<string, string>;
        /** The consent-approved set (null when no consent gate ran). */
        approved?: Set<string> | null;
        relay?: { sessionId: string; expiresAt: number };
    },
): string {
    const requested = (payload.requestedAttributes ?? []).filter(
        (k) => k !== 'sub' && ATTRIBUTE_MAP[k],
    );
    const shared: SharedAttributeTrace[] = [];
    for (const key of Object.keys(opts.sharedValues ?? {})) {
        if (key === 'sub') continue; // the sign-in itself, never listed
        const gov = assuranceFor(key, payload.attributeRequirements) === 'gov';
        // Gov attributes leave as enclave-signed proofs — never snapshot the
        // token (or the raw value); the marker is the honest record.
        shared.push(gov ? { key, gov: true } : { key, value: opts.sharedValues![key] });
    }
    const sharedKeys = new Set(shared.map((s) => s.key));
    const denied = opts.approved
        ? requested.filter((k) => !opts.approved!.has(k) && !sharedKeys.has(k))
        : [];
    const kind: SessionTrace['kind'] = payload.requestedBy
        ? 'device-auth'
        : payload.mode === 'session-relay' || payload.mode === 'voucher-only'
            ? 'relayed'
            : opts.attestation
                ? 'enclave'
                : 'sign-in';
    const att = opts.attestation
        ? [attestationTraceFrom(payload.appHost ?? payload.rpId, opts.attestation)]
        : undefined;
    return useServiceSessionsStore.getState().record({
        serviceKey: serviceKeyFor(payload),
        displayName: payload.appName,
        kind,
        // An OIDC client_id means the sign-in was brokered by our IdP; a bare
        // privasys.id RP likewise. Everything else is a plain passkey RP.
        identity:
            payload.clientId || payload.rpId.includes('privasys.id') ? 'privasys-id' : 'passkey',
        clientId: payload.clientId,
        rpId: payload.rpId,
        origin: payload.origin,
        appHost: payload.appHost,
        channel: opts.channel,
        requestedBy: payload.requestedBy,
        startedAt: Date.now(),
        expiresAt: opts.relay?.expiresAt,
        oneShot: kind === 'device-auth' || undefined,
        requestedAttributes: requested.length > 0 ? requested : undefined,
        sharedAttributes: shared.length > 0 ? shared : undefined,
        deniedAttributes: denied.length > 0 ? denied : undefined,
        attestations: att,
        sessionId: opts.relay?.sessionId,
    });
}

/**
 * What the consent screen must cover: every requested canonical attribute the
 * wallet could share — a present profile/device value, or an essential one the
 * acquisition step will collect. Optional attributes with no value cannot be
 * shared and are not asked about. `sub` is the sign-in itself, never listed.
 */
function buildConsentPlan(
    payload: QRPayload,
    profile: import('@/stores/profile').UserProfile | null,
): SignInConsentItem[] {
    const reqs = payload.attributeRequirements;
    return (payload.requestedAttributes ?? [])
        .filter((k) => k !== 'sub' && (ATTRIBUTE_MAP[k] || k === PRESENCE_KEY))
        .map((key) =>
            key === PRESENCE_KEY
                ? {
                    // Ceremonial: collected by the in-flow selfie check, so it
                    // is always "available" — the user decides on this screen
                    // whether the ceremony runs at all.
                    key,
                    label: attributeLabel(key),
                    essential: isEssential(key, reqs),
                    gov: true,
                    hasValue: true,
                }
                : {
                    key,
                    label: attributeLabel(key),
                    essential: isEssential(key, reqs),
                    gov: assuranceFor(key, reqs) === 'gov',
                    hasValue:
                        !!(profile && getProfileValue(profile, key)) ||
                        !!ATTRIBUTE_MAP[key]?.deviceSourced,
                })
        .filter((i) => i.hasValue || i.essential);
}

type FlowStep =
    | 'verifying'
    | 'confirm'
    | 'attestation'
    | 'attestation-changed'
    | 'consent'
    | 'selfie'
    | 'biometric'
    | 'authenticating'
    | 'acquire-attributes'
    | 'relaying'
    | 'done'
    | 'presence-failed'
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
    /** Paid-disclosure vouchers the IdP minted for the relying party, one per
     *  provider, each authorising a set of marketplace attribute keys. The
     *  wallet routes the matching voucher to the issuing enclave when disclosing
     *  a gov attribute; absent for free/unbilled requests. */
    disclosureVouchers?: import('@/services/kyc').DisclosureVoucher[];
    appName?: string;
    privacyPolicyUrl?: string;
    clientIP?: string;
    /** Optional, UNVERIFIED label naming an agent that brokered this request
     *  (CLI/agent device flow). When present the approval grants that agent a
     *  token that acts as the user, so we surface it prominently as a
     *  delegation warning. Never treat it as a verified identity. */
    requestedBy?: string;
    /** 'session-relay' — bootstrap a sealed session + bind the JWT (sign-in).
     *  'voucher-only' — extend a LIVE session to `appHost` with one biometric:
     *  attest + issue an EncAuth voucher (no WebAuthn, no relay); `sid` is the
     *  browser's session row to write to. 'standard' — plain passkey. */
    mode?: 'session-relay' | 'voucher-only' | 'standard';
    /** IdP session id (from the browser's JWT) to write the voucher to.
     *  Required for mode==='voucher-only'. */
    sid?: string;
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
    const insets = useSafeAreaInsets();
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
    const verificationMode = useSettingsStore((s) => s.verificationMode);
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
    // Field-level breakdown of WHAT changed vs the trusted record (app code,
    // config, platform), computed when entering the attestation-changed step.
    // Drives the kind-specific title/summary + "What changed" card.
    const [attestationDiff, setAttestationDiff] = useState<AttestationDiff | null>(null);
    // How the current attestation was established. Drives the badge in
    // AttestationView so the user can tell apart a fresh attestation-server
    // round-trip from a cache hit (and so we never silently accept either
    // when the target turned out to be a non-enclave service).
    const [verificationLevel, setVerificationLevel] = useState<AttestationVerificationLevel | null>(null);
    // The verification outcome (mode, challenged, and any failure) driving the
    // AttestationView recovery UX. Null → legacy behaviour (attestation.valid).
    const [verification, setVerification] = useState<VerificationState | null>(null);
    const [challengeInFlight, setChallengeInFlight] = useState(false);
    // The host actually attested, so the "Challenge this enclave" button can
    // re-verify the same target in challenge mode.
    const attestationTargetRef = useRef<string | null>(null);
    const hasStarted = useRef(false);

    // Attribute acquisition state — holds FIDO2 result while user provides missing profile data
    const [missingAttrs, setMissingAttrs] = useState<string[]>([]);
    // Sign-in consent: what the consent screen shows, which rows are on, and
    // the approved set the disclosure step is filtered by. The continuation is
    // the register/authenticate path stashed while the user decides.
    const [consentItems, setConsentItems] = useState<SignInConsentItem[]>([]);
    const [consentSelected, setConsentSelected] = useState<Set<string>>(new Set());
    const [consentRemember, setConsentRemember] = useState(true);
    // Fresh-presence result, so the terminal screen can be honest rather than a
    // blanket "Connected" when a live holder-presence check did not pass.
    const [presenceFail, setPresenceFail] = useState<{ retryable: boolean } | null>(null);
    const approvedAttrsRef = useRef<Set<string> | null>(null);
    const consentContinuation = useRef<(() => Promise<void>) | null>(null);
    // Fresh-presence ceremony (holder_present): selfie captured in-flow, then
    // matched in-enclave against the committed document portrait. The selfie
    // lives only in this ref for the duration of the ceremony.
    const selfieRef = useRef<string | null>(null);
    const selfieContinuation = useRef<(() => Promise<void>) | null>(null);
    const selfieCameraRef = useRef<CameraView>(null);
    const [selfiePermission, requestSelfiePermission] = useCameraPermissions();
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
                (payload.mode === 'session-relay' || payload.mode === 'voucher-only') && payload.appHost
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
                if ((payload.mode === 'session-relay' || payload.mode === 'voucher-only') && !hasMeasurements) {
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
                        await ensureConsentRef.current(payload, () =>
                            doAuthenticate(payload, credential.keyAlias, credential.credentialId, credential.serverRpId),
                        );
                        return;
                    }
                    // First time — register (FIDO2 handles biometric via NativeKeys)
                    await ensureConsentRef.current(payload, () => doRegister(payload));
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

                attestationTargetRef.current = attestationTarget;
                let result: AttestationResult;
                let level: AttestationVerificationLevel;
                if (reverifyDue) {
                    // Full verification through the attestation service, in the
                    // user's chosen mode (deterministic by default, or challenge
                    // — a fresh nonce bound to this TLS session). Mandatory on
                    // first connect and on periodic refresh.
                    const asToken = await getAttestationServerToken();
                    const reason = !trustedApp
                        ? 'first connect'
                        : !cachedMatch
                            ? 'cert measurements changed'
                            : cacheAgeMs > REVERIFY_TTL_MS
                                ? `cache age ${Math.round(cacheAgeMs / 60000)}m exceeds TTL`
                                : 'random sample';
                    console.log(`[CONNECT] attest (${reason}) mode=${verificationMode}`);
                    // Use whichever TEE family inspect() identified — hard-coding
                    // 'sgx' meant TDX containers failed with "expected SGX quote".
                    const outcome = await attestEnclave(attestationTarget, {
                        tee: inspectResult.tee_type ?? 'sgx',
                        mode: verificationMode,
                        attestationServerToken: asToken,
                    });
                    if (outcome.status !== 'verified' || !outcome.result) {
                        if (outcome.status === 'error') {
                            // Could not reach/handshake the enclave — nothing to
                            // proceed to. Hard-fail with a clear message.
                            throw new Error(
                                `Could not reach ${attestationTarget}: ${outcome.message ?? 'connection failed'}`
                            );
                        }
                        // unreachable (service down) or invalid (bad verdict):
                        // surface the recovery UX on the attestation screen —
                        // continue-anyway vs an explicit override — rather than a
                        // dead-end error. Show the inspected certificate.
                        console.warn(
                            `[CONNECT] attestation ${outcome.status} for ${attestationTarget}: ${outcome.message}`
                        );
                        setAttestation(inspectResult);
                        attestationRef.current = inspectResult;
                        setVerificationLevel(null);
                        setVerification({
                            status: outcome.status,
                            mode: outcome.mode,
                            challenged: outcome.challenged,
                            message: outcome.message,
                        });
                        setAttestationChanged(false);
                        setStep('attestation');
                        return;
                    }
                    result = outcome.result;
                    setVerification({ status: 'verified', mode: outcome.mode, challenged: outcome.challenged });
                    level = 'fresh-as-verified';
                } else {
                    console.log(
                        `[CONNECT] cached attestation trusted (last AS verify ${Math.round(cacheAgeMs / 60000)}m ago, ` +
                        `within ${REVERIFY_TTL_MS / 60000}m TTL)`
                    );
                    result = inspectResult;
                    level = 'cached-trusted';
                    // Verified from cache — deterministic by nature; the challenge
                    // button (deterministic mode) still lets the user demand a
                    // fresh liveness proof.
                    setVerification({ status: 'verified', mode: verificationMode, challenged: false });
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
                        // QR-initiated or within grace period: FIDO2 handles the
                        // biometric — but consent still gates any disclosure. The
                        // gate is silent when a remembered decision covers the set.
                        await ensureConsentRef.current(payload, () =>
                            doAuthenticate(payload, credential.keyAlias, credential.credentialId, credential.serverRpId),
                        );
                        return;
                    }
                    setStep('attestation');
                    return;
                }

                if (trustedApp) {
                    setAttestationChanged(true);
                    setAttestationDiff(diffTrustedAttestation(trustedApp, result));
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
        [getApp, isAttestationMatch, addTrustedApp, getCredentialForRp, checkUnlocked, gracePeriodSec, verificationMode]
    );

    /**
     * "Challenge this enclave" — force a fresh challenge-mode re-verification of
     * the currently-shown enclave. Sends a brand-new random nonce so the enclave
     * folds it plus the TLS channel binder into a fresh quote, proving liveness
     * and binding the attestation to this exact session. Available from the
     * approval screen when the default mode is deterministic.
     */
    const handleChallenge = useCallback(async () => {
        const target = attestationTargetRef.current;
        const att = attestationRef.current;
        if (!target || !att) return;
        setChallengeInFlight(true);
        try {
            const asToken = await getAttestationServerToken();
            const outcome = await attestEnclave(target, {
                tee: att.tee_type ?? 'sgx',
                mode: 'challenge',
                attestationServerToken: asToken,
            });
            if (outcome.status === 'verified' && outcome.result) {
                setAttestation(outcome.result);
                attestationRef.current = outcome.result;
                setVerificationLevel('fresh-as-verified');
                setVerification({ status: 'verified', mode: 'challenge', challenged: true });
            } else if (outcome.status === 'error') {
                // Lost the connection mid-challenge — keep the prior view, just
                // tell the user it couldn't run.
                Alert.alert('Challenge failed', outcome.message ?? 'Could not reach the enclave.');
            } else {
                // The challenge surfaced a problem (or the service was down):
                // show the recovery UX inline.
                setVerification({
                    status: outcome.status,
                    mode: outcome.mode,
                    challenged: outcome.challenged,
                    message: outcome.message,
                });
            }
        } finally {
            setChallengeInFlight(false);
        }
    }, []);

    /**
     * Consent gate for the sign-in flow. Before any register/authenticate
     * continuation runs (and so before any attribute leaves the wallet), the
     * user must have approved the shareable set for THIS relying party:
     *  - nothing shareable → proceed, with an empty approved set;
     *  - a remembered ("always share") decision that already covers every
     *    requested attribute → proceed silently with the remembered set;
     *  - otherwise show the consent screen. Essential attributes are locked
     *    on; optional gov-assurance ones default OFF (explicit opt-in),
     *    optional profile ones default ON, and prior per-attribute decisions
     *    are preserved. A request that grows the attribute set re-prompts.
     */
    /** Interpose the fresh-presence ceremony when the approved set includes
     *  holder_present: a selfie is required EVERY time (that is the point —
     *  a remembered consent never skips the live check), so route through the
     *  selfie step before the continuation runs. */
    const runWithPresence = useCallback(
        async (approved: Set<string>, cont: () => Promise<void>) => {
            if (approved.has(PRESENCE_KEY)) {
                selfieRef.current = null;
                selfieContinuation.current = cont;
                setStep('selfie');
                return;
            }
            await cont();
        },
        [],
    );

    /** Choose the terminal screen from the presence result: a passed/absent
     *  presence lands on the normal "Connected" success; a FAILED live check
     *  (the v0.6.0 signed failure receipt) lands on an honest "couldn't confirm
     *  it's you" screen instead of a misleading green. The sign-in itself still
     *  completed and the truthful receipt was already relayed to the relying
     *  party — this only fixes what the USER is shown. Returns true when it
     *  routed to the failure screen (so the caller skips the auto-return). */
    const routeTerminal = useCallback(
        (payload: QRPayload, attributes?: Record<string, string>): boolean => {
            const po = presenceOutcome(payload, attributes, !!selfieRef.current);
            if (po === 'failed-retryable' || po === 'failed-final') {
                setPresenceFail({ retryable: po === 'failed-retryable' });
                setStep('presence-failed');
                return true;
            }
            setStep('done');
            return false;
        },
        [],
    );

    // Reads live state (profile store + attestationRef) rather than closing over
    // it, so it is a STABLE callback safe to call from startFlow's fast paths
    // (which are defined earlier and memoised on their own deps).
    const ensureConsentThen = useCallback(
        async (payload: QRPayload, cont: () => Promise<void>) => {
            const currentProfile = useProfileStore.getState().profile;
            const plan = buildConsentPlan(payload, currentProfile);
            if (plan.length === 0) {
                approvedAttrsRef.current = new Set();
                await cont();
                return;
            }
            const key = consentKeyFor(payload);
            const att = attestationRef.current;
            const meas = att?.mrtd ?? att?.mrenclave ?? '';
            const codeHash = att?.workload_code_hash ?? '';
            const consent = useConsentStore.getState();
            const standing = consent.getStandingConsent(key, meas, codeHash);
            const latest = consent.getRecordsForApp(key)[0];
            const decided = new Set(latest?.requestedAttributes ?? []);
            // Skip the screen only when a remembered decision already covers
            // every requested attribute for this exact enclave measurement.
            if (
                standing &&
                latest?.persistent &&
                plan.every((i) => decided.has(i.key))
            ) {
                approvedAttrsRef.current = new Set(standing.attributes);
                // A remembered decision can skip the consent SCREEN, never the
                // live presence check.
                await runWithPresence(approvedAttrsRef.current, cont);
                return;
            }
            const prevApproved = new Set(standing?.attributes ?? []);
            setConsentItems(plan);
            setConsentSelected(
                new Set(
                    plan
                        .filter((i) =>
                            i.essential ||
                            (decided.has(i.key) ? prevApproved.has(i.key) : !i.gov),
                        )
                        .map((i) => i.key),
                ),
            );
            setConsentRemember(true);
            consentContinuation.current = cont;
            setStep('consent');
        },
        [],
    );
    const ensureConsentRef = useRef(ensureConsentThen);
    ensureConsentRef.current = ensureConsentThen;

    /** User confirmed the consent screen: record the decision (and standing
     *  consent when asked to remember), then run the stashed continuation with
     *  the approved set gating every disclosure. */
    const handleConsentApprove = useCallback(async () => {
        if (!qr) return;
        const key = consentKeyFor(qr);
        const att = attestationRef.current ?? attestation;
        const meas = att?.mrtd ?? att?.mrenclave ?? '';
        const codeHash = att?.workload_code_hash ?? '';
        const teeType =
            att?.tee_type === 'sgx' || att?.tee_type === 'tdx' ||
            att?.tee_type === 'sev-snp' || att?.tee_type === 'nvidia-gpu'
                ? att.tee_type
                : ('none' as const);
        const approved = consentItems.filter((i) => consentSelected.has(i.key)).map((i) => i.key);
        const denied = consentItems.filter((i) => !consentSelected.has(i.key)).map((i) => i.key);
        const now = Math.floor(Date.now() / 1000);
        const consent = useConsentStore.getState();
        consent.addRecord({
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
            rpId: key,
            origin: qr.rpId,
            appName: qr.appName,
            requestedAttributes: consentItems.map((i) => i.key),
            approvedAttributes: approved,
            deniedAttributes: denied,
            decision: denied.length === 0 ? 'approved' : approved.length === 0 ? 'denied' : 'partial',
            persistent: consentRemember,
            teeType,
            enclaveMeasurement: meas,
            codeHash,
            consentedAt: now,
            expiresAt: 0,
        });
        if (consentRemember) {
            consent.setStandingConsent({
                rpId: key,
                attributes: approved,
                enclaveMeasurement: meas,
                codeHash,
                grantedAt: now,
            });
        }
        approvedAttrsRef.current = new Set(approved);
        const cont = consentContinuation.current;
        consentContinuation.current = null;
        if (cont) await runWithPresence(approvedAttrsRef.current, cont);
    }, [qr, attestation, consentItems, consentSelected, consentRemember, runWithPresence]);

    const toggleConsentAttr = useCallback((key: string) => {
        setConsentSelected((prev) => {
            const next = new Set(prev);
            if (next.has(key)) next.delete(key);
            else next.add(key);
            return next;
        });
    }, []);

    /** Capture the presence selfie and resume the sign-in continuation. */
    const handleSelfieCapture = useCallback(async () => {
        try {
            if (selfiePermission && !selfiePermission.granted) {
                const res = await requestSelfiePermission();
                if (!res.granted) {
                    Alert.alert(
                        'Camera needed',
                        'The presence check matches a quick selfie to your ID photo inside the secure enclave. Without the camera it will be skipped.',
                    );
                    return;
                }
            }
            const photo = await selfieCameraRef.current?.takePictureAsync({
                base64: true,
                quality: 0.6,
            });
            if (!photo?.base64) throw new Error('Could not capture a selfie');
            selfieRef.current = photo.base64;
            const cont = selfieContinuation.current;
            selfieContinuation.current = null;
            if (cont) await cont();
        } catch (e: any) {
            Alert.alert('Presence check', e?.message ?? 'Camera error');
        }
    }, [selfiePermission, requestSelfiePermission]);

    /** User declined the live check: drop holder_present (the relying party
     *  sees the absence and applies its own policy) and continue signing in. */
    const handleSelfieSkip = useCallback(async () => {
        approvedAttrsRef.current?.delete(PRESENCE_KEY);
        selfieRef.current = null;
        const cont = selfieContinuation.current;
        selfieContinuation.current = null;
        if (cont) await cont();
    }, []);

    const handleConfirm = useCallback(async () => {
        if (!qr) return;
        const credential = getCredentialForRp(qr.rpId);
        if (!credential) return;

        // Consent first — the disclosure step is gated by what it approves.
        await ensureConsentThen(qr, async () => {
            // Go directly to FIDO2 — NativeKeys.sign() handles biometric.
            await doAuthenticate(qr, credential.keyAlias, credential.credentialId, credential.serverRpId);
        });
    }, [qr, ensureConsentThen]);

    const handleApprove = useCallback(async () => {
        if (!qr || !attestation) return;

        // Voucher-only: extend the live session to this enclave (one biometric,
        // no sign-in). Handled separately — no WebAuthn registration/relay.
        if (qr.mode === 'voucher-only') {
            await doVoucherOnly(qr);
            return;
        }

        // Consent first — the disclosure step is gated by what it approves.
        await ensureConsentThen(qr, async () => {
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
        });
    }, [qr, attestation, attestationChanged, ensureConsentThen]);

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

    /** Voucher-only approval: extend a LIVE browser session to an additional
     *  enclave (`qr.appHost`) with a SINGLE biometric — no sign-in ceremony,
     *  no relay. Reuses the credential the user already has for `qr.rpId`:
     *   1. FIDO2 authenticate against that credential → a fresh wallet session
     *      token + the pairwise sub (one biometric; its grace window covers the
     *      voucher signature that follows);
     *   2. bootstrap `appHost` with the browser-supplied throwaway sdkPub to
     *      read the enclave's enc_pub;
     *   3. sign + upload the EncAuth voucher for `appHost` (lands on the same
     *      IdP session row the browser polls, since it's the same
     *      (user, client_id, device) tuple).
     *  The browser's poll then sees the new voucher and resumes the sealed
     *  session silently. */
    const doVoucherOnly = async (payload: QRPayload) => {
        const att = attestationRef.current ?? attestation;
        if (!att) {
            setError('No verified attestation for this app.');
            return;
        }
        if (!payload.appHost || !payload.clientId || !payload.sdkPub || !payload.sid) {
            setError('Malformed approval request (missing appHost/clientId/sdkPub/sid).');
            return;
        }
        const credential = getCredentialForRp(payload.rpId);
        if (!credential) {
            setError(`No credential for ${payload.rpId}. Sign in first, then add the tool.`);
            return;
        }
        setStep('authenticating');
        try {
            // 1. Authenticate against the existing credential to mint a fresh
            //    wallet session token (and get the pairwise sub). No relay.
            // Use the bare IdP host (rpId) as the FIDO2 fetch host. `origin`
            // may arrive scheme-prefixed ("https://privasys.id"), which the
            // native RA-TLS layer would resolve to host "https" and fail DNS.
            const auth = await fido2.authenticate(
                payload.rpId,
                credential.keyAlias,
                credential.credentialId,
                payload.sid, // correlation only; no browser relay on this path
                credential.serverRpId,
            );
            if (!auth.sessionToken || !auth.userId) {
                throw new Error('authentication did not return a session');
            }
            // 2. Bootstrap the enclave to read its enc_pub (throwaway sdkPub).
            const bs = await fido2.bootstrapHost(payload.appHost, payload.sdkPub);
            // 3. Sign + upload the voucher for this host.
            await issueEncAuthForSignIn({
                walletSessionToken: auth.sessionToken,
                keyId: credential.keyAlias,
                clientId: payload.clientId,
                sub: auth.userId,
                encPubB64: bs.encPub,
                quoteHashHex: deriveQuoteHash(att),
                attestation: att,
                host: payload.appHost,
            });
            // Surface the newly-trusted enclave on the Home tab.
            addTrustedApp({
                rpId: payload.appHost,
                origin: payload.appHost,
                appName: payload.appName ?? payload.appHost,
                mrenclave: att.mrenclave,
                mrtd: att.mrtd,
                codeHash: att.workload_code_hash,
                configRoot: att.workload_config_merkle_root,
                teeType: att.tee_type || 'sgx',
                lastVerified: Math.floor(Date.now() / 1000),
                credentialId: '', // voucher-only trust row (no passkey on this host)
            });
            // Audit trail: the user was asked to authenticate to extend the
            // sealed session to this enclave — a ceremony in its own right.
            recordCeremonyTrace(payload, {
                channel: params.source === 'push' ? 'push' : 'qr',
                attestation: att,
            });
            setStep('done');
            console.log(`[CONNECT] voucher-only: issued voucher for ${payload.appHost}`);
            // Return to Home like the other success paths — without this the
            // "Connected" screen is a dead end and the only way out is to kill
            // the app.
            setTimeout(() => router.replace('/(tabs)'), 1500);
        } catch (e: any) {
            console.error('[CONNECT] voucher-only failed:', e?.message ?? e);
            setError(`Could not add ${payload.appHost}: ${e?.message ?? e}`);
            setStep('error');
        }
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
        // Background flow: verify in the user's default mode (deterministic
        // unless they opted into challenge) and always through the attestation
        // service. No UI here — a non-verified outcome throws so the caller
        // skips just this host.
        const outcome = await attestEnclave(host, {
            tee: inspected.tee_type ?? 'sgx',
            mode: verificationMode,
            attestationServerToken: asToken,
        });
        if (outcome.status !== 'verified' || !outcome.result) {
            throw new Error(`attestation ${outcome.status} for ${host}: ${outcome.message ?? ''}`);
        }
        // Merge: inspect carries the rich OID-derived fields the voucher hashes,
        // verify carries the authoritative measurements/validity.
        return { ...inspected, ...outcome.result };
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
        ceremonyTraceId?: string,
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
                // One ceremony = one trace: companion enclaves sealed under the
                // same unlock attach to the primary trace rather than fabricating
                // a second "session" the user never separately approved.
                if (ceremonyTraceId) {
                    useServiceSessionsStore
                        .getState()
                        .attachAttestation(ceremonyTraceId, attestationTraceFrom(host, att));
                }
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
            const attributes = await resolveRequestedAttributes(payload, profile, approvedAttrsRef.current, selfieRef.current);

            await relaySessionToken(
                payload.brokerUrl,
                payload.sessionId,
                result.sessionToken,
                pushToken,
                attributes,
                result.sessionRelay,
            );

            // IdP-brokered flows: ALSO patch the attributes onto the auth code
            // directly. In the SDK (iframe) flow the frame-host relays them to
            // /session/complete for us, but in the DEVICE flow nobody listens
            // on the relay — without this call the ceremony's disclosures
            // (including paid gov proofs the RP was already charged for) never
            // reach the issued tokens. The IdP's patch branch is idempotent,
            // so double delivery via the SDK path is harmless.
            await patchSessionAttributes(payload, attributes);

            // Relay succeeded — now persist locally.
            persistCredentialAndTrust(payload, result.credentialId, keyAlias, result.userHandle, result.userName, result.serverRpId);

            // Register the push token under THIS pairwise identity's session so
            // the IdP can push vault approvals for keys this identity owns. The
            // IdP learns no linkage it doesn't already have (it sees each
            // pairwise sub independently). Best-effort.
            if (pushToken && result.sessionToken) {
                registerPushTokenWithIdp(result.sessionToken, pushToken).catch((e) =>
                    console.warn('[CONNECT] push-token registration (pairwise) failed', e),
                );
            }

            // Surface the live sealed session on the Home screen so the
            // user sees the relay countdown next to the connected service.
            let relayInfo: { sessionId: string; expiresAt: number } | undefined;
            if (result.sessionRelay) {
                const safeExpiresAt = sanitizeRelayExpiresAt(result.sessionRelay.expiresAt);
                console.log(
                    `[CONNECT] registering relay session on Home: sessionId=${result.sessionRelay.sessionId.substring(0, 8)}... rawExpiresAt=${result.sessionRelay.expiresAt} safeExpiresAt=${safeExpiresAt} (in ${Math.round((safeExpiresAt - Date.now()) / 1000)}s)`
                );
                relayInfo = { sessionId: result.sessionRelay.sessionId, expiresAt: safeExpiresAt };
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

            // Audit trail: one trace per ceremony, keyed by the APP (client),
            // carrying what was requested/shared and the verified attestation.
            const traceId = recordCeremonyTrace(payload, {
                channel: params.source === 'push' ? 'push' : 'qr',
                attestation: attestationRef.current ?? attestation,
                sharedValues: attributes,
                approved: approvedAttrsRef.current,
                relay: relayInfo,
            });

            // Upload the silent-rebind voucher while the keystore's
            // biometric grace (where supported) still covers the extra
            // hardware signature.
            maybeIssueEncAuth(payload, keyAlias, result, sessionRelayArg);
            // Multi-app attestation: seal any extra enclave hosts in the same
            // ceremony (back-to-back, under the one biometric grace window).
            void issueExtraAppVouchers(payload, keyAlias, result, traceId);

            // Warm the personal drive after login so the Drive tab is instant.
            // Gated behind the (in-progress) driveEnabled setting; best-effort.
            if (useSettingsStore.getState().driveEnabled) {
                void ensureDrive().catch((e) =>
                    console.warn('[CONNECT] drive setup skipped:', e?.message ?? e),
                );
            }

            // Start biometric grace period (skips push confirmation for subsequent auths).
            if (gracePeriodSec > 0) setUnlocked(gracePeriodSec * 1000);

            if (!routeTerminal(payload, attributes)) {
                setTimeout(() => router.replace('/(tabs)'), 1500);
            }
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
            const attributes = await resolveRequestedAttributes(payload, profile, approvedAttrsRef.current, selfieRef.current);

            await relaySessionToken(
                payload.brokerUrl,
                payload.sessionId,
                result.sessionToken,
                pushToken,
                attributes,
                result.sessionRelay,
            );

            // Device-flow attribute delivery (see patchSessionAttributes).
            await patchSessionAttributes(payload, attributes);

            // Keep the IdP's push target fresh for this pairwise identity
            // (vault approvals for keys it owns). Best-effort.
            if (pushToken && result.sessionToken) {
                registerPushTokenWithIdp(result.sessionToken, pushToken).catch((e) =>
                    console.warn('[CONNECT] push-token registration (pairwise) failed', e),
                );
            }

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
            let relayInfo: { sessionId: string; expiresAt: number } | undefined;
            if (result.sessionRelay) {
                const safeExpiresAt = sanitizeRelayExpiresAt(result.sessionRelay.expiresAt);
                console.log(
                    `[CONNECT] registering relay session on Home: sessionId=${result.sessionRelay.sessionId.substring(0, 8)}... rawExpiresAt=${result.sessionRelay.expiresAt} safeExpiresAt=${safeExpiresAt} (in ${Math.round((safeExpiresAt - Date.now()) / 1000)}s)`
                );
                relayInfo = { sessionId: result.sessionRelay.sessionId, expiresAt: safeExpiresAt };
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

            // Audit trail: one trace per ceremony, keyed by the APP (client).
            const traceId = recordCeremonyTrace(payload, {
                channel: params.source === 'push' ? 'push' : 'qr',
                attestation: attestationRef.current ?? attestation,
                sharedValues: attributes,
                approved: approvedAttrsRef.current,
                relay: relayInfo,
            });

            // Upload the silent-rebind voucher while the keystore's
            // biometric grace (where supported) still covers the extra
            // hardware signature.
            maybeIssueEncAuth(payload, keyAlias, result, sessionRelayArg);
            // Multi-app attestation: seal any extra enclave hosts in the same
            // ceremony (back-to-back, under the one biometric grace window).
            void issueExtraAppVouchers(payload, keyAlias, result, traceId);

            // Warm the personal drive after login so the Drive tab is instant.
            // Gated behind the (in-progress) driveEnabled setting; best-effort.
            if (useSettingsStore.getState().driveEnabled) {
                void ensureDrive().catch((e) =>
                    console.warn('[CONNECT] drive setup skipped:', e?.message ?? e),
                );
            }

            // Start biometric grace period (skips push confirmation for subsequent auths).
            if (gracePeriodSec > 0) setUnlocked(gracePeriodSec * 1000);

            if (!routeTerminal(payload, attributes)) {
                setTimeout(() => router.replace('/(tabs)'), 1500);
            }
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
            const attributes = await resolveRequestedAttributes(pending.payload, updatedProfile, approvedAttrsRef.current, selfieRef.current);

            await relaySessionToken(
                pending.payload.brokerUrl,
                pending.payload.sessionId,
                pending.sessionToken,
                pushToken,
                attributes,
            );

            // Device-flow attribute delivery (see patchSessionAttributes).
            await patchSessionAttributes(pending.payload, attributes);

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

            // Audit trail (no sealed relay rides this late-relay path).
            recordCeremonyTrace(pending.payload, {
                channel: params.source === 'push' ? 'push' : 'qr',
                attestation: attestationRef.current ?? attestation,
                sharedValues: attributes,
                approved: approvedAttrsRef.current,
            });

            pendingRelay.current = null;
            if (!routeTerminal(pending.payload, attributes)) {
                setTimeout(() => router.replace('/(tabs)'), 1500);
            }
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
                            {/* What this sign-in actually connects to. For a
                                session-relay flow the sealed session binds to the
                                enclave at `appHost` (verified on the next screen),
                                not the IdP rpId above — surface it so the user can
                                see the real endpoint before approving. */}
                            {qr.appHost && qr.appHost !== qr.rpId && (
                                <View style={styles.confirmEndpointRow}>
                                    <Ionicons name="lock-closed" size={12} color="#0F766E" />
                                    <Text style={styles.confirmEndpoint}>{qr.appHost}</Text>
                                </View>
                            )}
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
                        verification={verification ?? undefined}
                        onApprove={handleApprove}
                        onReject={handleReject}
                        onChallenge={handleChallenge}
                        challengeInFlight={challengeInFlight}
                    />
                )}

                {step === 'attestation-changed' && attestation && qr && (
                    <AttestationView
                        attestation={attestation}
                        rpId={qr.rpId}
                        displayName={appName(qr.rpId)}
                        isChanged={true}
                        diff={attestationDiff}
                        verificationLevel={verificationLevel}
                        verification={verification ?? undefined}
                        onApprove={handleApprove}
                        onReject={handleReject}
                        onChallenge={handleChallenge}
                        challengeInFlight={challengeInFlight}
                    />
                )}

                {step === 'consent' && qr && (
                    <RNView style={{ flex: 1, paddingTop: insets.top }}>
                        <DataRequestConsent
                            appName={qr.appName || appName(qr.rpId)}
                            origin={qr.clientId || qr.rpId}
                            sectionTitle="THIS SERVICE WILL RECEIVE"
                            sectionDescription="Choose what to share. Items marked required are needed to sign in."
                            items={consentItems.map((i) => ({
                                key: i.key,
                                label: i.label,
                                sublabel: i.key === PRESENCE_KEY
                                    ? (i.essential ? 'Required · ' : '') +
                                      'Quick selfie matched to your ID in the enclave'
                                    : !i.hasValue
                                        ? 'Will be verified during sign-in'
                                        : i.gov
                                            ? i.essential
                                                ? 'Required · passport-verified proof'
                                                : 'Passport-verified proof'
                                            : i.essential
                                                ? 'Required'
                                                : undefined,
                                missing: !i.hasValue,
                                toggle: {
                                    value: consentSelected.has(i.key),
                                    onChange: () => toggleConsentAttr(i.key),
                                    disabled: i.essential,
                                },
                            }))}
                            note={
                                consentItems.some((i) => i.gov)
                                    ? 'Verified attributes are shared as enclave-signed proofs bound to this service — never the raw document. The service pays for them; you pay nothing.'
                                    : undefined
                            }
                            persistent={{ value: consentRemember, onChange: setConsentRemember }}
                            approveLabel="Share"
                            approveCount={consentSelected.size}
                            onDeny={handleReject}
                            onApprove={handleConsentApprove}
                        />
                    </RNView>
                )}

                {step === 'selfie' && (
                    <RNView style={styles.selfieContainer}>
                        <CameraView ref={selfieCameraRef} style={styles.selfieCamera} facing="front" />
                        <RNView style={[styles.selfieOverlay, { paddingBottom: insets.bottom + 24 }]}>
                            <Text style={styles.selfieTitle}>Confirm it&apos;s you</Text>
                            <Text style={styles.selfieText}>
                                {(qr?.appName || 'This service') +
                                    ' asked to confirm you are physically present. Your selfie is matched to your ID photo inside the secure enclave, then discarded.'}
                            </Text>
                            <Pressable style={styles.selfieCaptureButton} onPress={handleSelfieCapture}>
                                <Text style={styles.selfieCaptureText}>Take selfie</Text>
                            </Pressable>
                            <Pressable onPress={handleSelfieSkip} hitSlop={8}>
                                <Text style={styles.selfieSkipText}>Don&apos;t confirm presence</Text>
                            </Pressable>
                        </RNView>
                    </RNView>
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
                        {/* Explicit exit so the screen is never a dead end, even
                            if the auto-return timer is missed. */}
                        <Pressable style={styles.secondaryButton} onPress={() => router.replace('/(tabs)')}>
                            <Text style={styles.secondaryButtonText}>Done</Text>
                        </Pressable>
                    </View>
                )}

                {step === 'presence-failed' && (
                    <View style={styles.centered}>
                        <Text style={styles.errorIcon}>⚠</Text>
                        <Text style={styles.title}>Couldn&apos;t confirm it&apos;s you</Text>
                        <Text style={styles.subtitle}>
                            {presenceFail?.retryable
                                ? 'The live selfie didn’t match your ID photo. Make sure it’s you, in good light, and try the sign-in again.'
                                : 'The presence check didn’t pass. Contact the service if you believe this is an error.'}
                        </Text>
                        <Text style={styles.presenceNote}>
                            You have been signed in, but the service was told the presence
                            check did not pass and may not let you continue.
                        </Text>
                        <Pressable style={styles.secondaryButton} onPress={() => router.replace('/(tabs)')}>
                            <Text style={styles.secondaryButtonText}>Done</Text>
                        </Pressable>
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
    presenceNote: { fontSize: 13, textAlign: 'center', opacity: 0.55, marginBottom: 24, paddingHorizontal: 8 },
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
    selfieContainer: { flex: 1, backgroundColor: '#000' },
    selfieCamera: { flex: 1 },
    selfieOverlay: {
        position: 'absolute',
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0,0,0,0.72)',
        paddingHorizontal: 24,
        paddingTop: 20,
        gap: 12,
        alignItems: 'center'
    },
    selfieTitle: { fontSize: 20, fontWeight: '700', color: '#FFFFFF' },
    selfieText: { fontSize: 14, color: '#E5E7EB', textAlign: 'center', lineHeight: 20 },
    selfieCaptureButton: {
        backgroundColor: '#007AFF',
        borderRadius: 12,
        paddingVertical: 14,
        paddingHorizontal: 48,
        alignSelf: 'stretch',
        alignItems: 'center'
    },
    selfieCaptureText: { fontSize: 16, fontWeight: '600', color: '#FFFFFF' },
    selfieSkipText: { fontSize: 14, color: '#9CA3AF', paddingVertical: 6 },
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
    confirmEndpointRow: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 6,
        backgroundColor: 'rgba(15, 118, 110, 0.08)',
        borderRadius: 8,
        paddingHorizontal: 10,
        paddingVertical: 6,
        marginBottom: 12
    },
    confirmEndpoint: {
        fontSize: 13,
        fontFamily: 'Inter',
        color: '#0F766E',
        flexShrink: 1
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
