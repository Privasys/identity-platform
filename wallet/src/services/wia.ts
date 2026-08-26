// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Wallet Instance Attestation (WIA).
 *
 * Proves to the IdP (as wallet provider) that the wallet's hardware holder key
 * lives in genuine hardware inside our genuine app, and caches the short-lived
 * WIA JWT the IdP returns (cnf.jwk = holder key). The verifier enclave requires
 * a valid WIA before it will run a (free) identity verification, so free KYC is
 * wallet-only by construction. See attribute-billing-plan §3.
 *
 * Enrolment is LAZY, never at cold start: proving possession signs the fresh
 * challenge with the biometric-gated holder key, so it must happen inside a flow
 * where the user already expects Face ID / fingerprint (the KYC verification).
 * Attaching the cached WIA to a request, by contrast, never prompts.
 */

import Constants from 'expo-constants';
import * as Crypto from 'expo-crypto';
import { Platform } from 'react-native';

import { useAuthStore } from '@/stores/auth';
import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';
import * as SecureStore from '@/utils/storage';

import * as AppAttest from '../../modules/app-attest/src/index';
import { signWithDeviceKey } from './did';
import * as NativeKeys from '../../modules/native-keys/src/index';
import { ensurePrivasysSession } from './privasys-id';

const IDP_BASE_URL = process.env['EXPO_PUBLIC_IDP_URL'] || 'https://privasys.id';

/** Same stable device holder key the IVR binds to (kyc.ts HOLDER_KEY_ID). */
const HOLDER_KEY_ID = 'privasys-wallet-default';

/** Sealed cache of the current WIA. */
const WIA_STORE_KEY = 'privasys.wia';

/** Re-enrol this long before expiry so a request never rides an about-to-expire WIA. */
const REFRESH_SKEW_MS = 60 * 60 * 1000; // 1h

interface StoredWia {
    jwt: string;
    expiresAt: number; // unix ms
}

let inflight: Promise<string | null> | null = null;

/**
 * Why the last enrolment attempt failed, or null if none has.
 *
 * Enrolment is best-effort and swallows its error, which is right for the
 * endpoints that work without a WIA. It is wrong for the endpoints that do not:
 * they used to upload a large body and receive a connection reset, because the
 * runtime's gate refuses an unexempt call before draining the request. Keeping
 * the reason lets those callers refuse locally and say why (2026-08-26).
 */
let lastEnrolError: string | null = null;

/** The reason the most recent enrolment failed, for callers that must have a WIA. */
export function lastWiaError(): string | null {
    return lastEnrolError;
}

/** The cached WIA if present and comfortably unexpired, else null. Never prompts. */
export async function getValidWia(): Promise<string | null> {
    try {
        const raw = await SecureStore.getItemAsync(WIA_STORE_KEY);
        if (!raw) return null;
        const s = JSON.parse(raw) as StoredWia;
        if (s.jwt && s.expiresAt - REFRESH_SKEW_MS > Date.now()) return s.jwt;
        return null;
    } catch {
        return null;
    }
}

/**
 * Return a valid WIA, enrolling (or refreshing) if needed. Enrolment proves
 * possession of the holder key (a biometric-gated signature), so only call this
 * from a flow where a biometric prompt is expected. Best-effort by contract: the
 * caller treats a thrown/na result as "no WIA" and proceeds (the enclave gate is
 * fail-open during rollout).
 */
export async function ensureWia(): Promise<string | null> {
    const cached = await getValidWia();
    if (cached) return cached;
    if (inflight) return inflight;
    inflight = enrol().finally(() => {
        inflight = null;
    });
    return inflight;
}

/** Drop the cached WIA (e.g. on sign-out / holder-key rotation). */
export async function clearWia(): Promise<void> {
    try {
        await SecureStore.deleteItemAsync(WIA_STORE_KEY);
    } catch {
        /* ignore */
    }
}

async function walletSessionToken(): Promise<string> {
    // Reuse the cached wallet session when still valid so enrolment adds no
    // extra sign-in prompt; otherwise fall through to a (biometric) sign-in.
    const acct = useAuthStore.getState().privasysId;
    if (acct?.sessionToken && Date.now() < acct.sessionExpiresAt) return acct.sessionToken;
    const s = await ensurePrivasysSession();
    return s.sessionToken;
}

async function idp<T>(path: string, token: string, body: unknown): Promise<T> {
    const res = await fetch(`${IDP_BASE_URL}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer wallet:${token}` },
        body: JSON.stringify(body ?? {})
    });
    if (!res.ok) {
        throw new Error(`WIA ${path} failed (${res.status}): ${(await res.text()).slice(0, 200)}`);
    }
    return (await res.json()) as T;
}

async function enrol(): Promise<string | null> {
    try {
        const token = await walletSessionToken();

        const { challenge } = await idp<{ challenge: string; expires_in: number }>(
            '/wia/challenge',
            token,
            {}
        );

        // Proof of possession: sign the fresh challenge with the holder key.
        // signWithDeviceKey takes base64url data and signs its decoded bytes
        // (with an internal SHA-256), which is exactly what the IdP verifies.
        //
        // Signed first so a key the hardware has retired is reported as such,
        // rather than as a public key read from a key that cannot sign.
        const holderSig = await signWithDeviceKey(challenge, HOLDER_KEY_ID);
        const holderPub = (await NativeKeys.getPublicKey(HOLDER_KEY_ID)).publicKey; // b64url SEC1

        // Never post a half-built proof. The iOS module used to report failure
        // by RETURNING an error object, so these came through as undefined,
        // JSON.stringify dropped them, and the IdP answered "holder
        // proof-of-possession signature is invalid" — an accurate statement
        // about an empty signature that read as a cryptographic fault
        // (2026-08-26). NativeKeys now throws, and this is the belt to that
        // brace: a future native change cannot quietly reintroduce it.
        if (!holderPub) throw new Error('holder public key unavailable');
        if (!holderSig) throw new Error('holder key produced no signature');

        const attestation = await acquireDeviceAttestation(challenge, holderPub);
        if (!attestation) return null; // no attestation available (e.g. simulator) → skip, stay WIA-less

        const platform = Platform.OS === 'ios' ? 'ios' : 'android';
        const walletVersion =
            (Constants.expoConfig?.version as string | undefined) ??
            (Constants.expoConfig?.extra?.['CODE_VERSION'] as string | undefined) ??
            '';

        const out = await idp<{ wia: string; expires_at: number; level: string }>(
            '/wia/enrol',
            token,
            {
                platform,
                holder_pub: holderPub,
                challenge,
                holder_sig: holderSig,
                attestation,
                wallet_version: walletVersion
            }
        );

        const stored: StoredWia = { jwt: out.wia, expiresAt: out.expires_at * 1000 };
        await SecureStore.setItemAsync(WIA_STORE_KEY, JSON.stringify(stored));
        return out.wia;
    } catch (e) {
        // Soft rollout: enrolment failures must never break identity verification.
        lastEnrolError = e instanceof Error ? e.message : String(e);
        console.warn('[WIA] enrolment skipped:', lastEnrolError);
        return null;
    }
}

/**
 * Produce the platform device-integrity evidence the IdP validates, bound to
 * this challenge and holder key. iOS uses App Attest (the App Attest nonce
 * commits to clientDataHash = SHA-256(challenge ‖ holder_pub)); Android uses a
 * Play Integrity token over the same client-data hash. Returns null when device
 * attestation is unavailable, so the wallet degrades to WIA-less rather than
 * throwing during the soft rollout.
 *
 * iOS uses a FRESH, WIA-scoped App Attest key per enrolment (reset → generate
 * → attest), so every enrol carries a full attestation object — the shape the
 * IdP's strict mode requires. A key attests only once, and the legacy key is
 * shared with the attestation-server flow, so reusing keys degrades to
 * assertions that strict mode rejects. Keys are cheap; enrolment is rare
 * (WIA TTL is days), so a per-enrol key costs one Apple round-trip.
 */
const WIA_ATTEST_SCOPE = 'wia';

async function acquireDeviceAttestation(
    challengeB64url: string,
    holderPubB64url: string
): Promise<Record<string, unknown> | null> {
    try {
        const state = await AppAttest.getState(WIA_ATTEST_SCOPE);
        if (!state.supported) return null;

        if (Platform.OS === 'ios') {
            // Fresh key per enrolment → always a full attestation object.
            //
            // Pass the RAW client data (challenge ‖ holder_pub), NOT its hash:
            // the native module SHA-256-hashes its input once before calling
            // DCAppAttestService (App Attest takes a clientDataHash), so the
            // nonce Apple certifies is SHA-256(authData ‖ SHA-256(clientData))
            // — exactly what the IdP recomputes. A pre-hashed value here gets
            // hashed a second time and enrolment fails with "nonce does not
            // bind this challenge and holder key".
            await AppAttest.reset(WIA_ATTEST_SCOPE);
            const keyId = await AppAttest.generateKey(WIA_ATTEST_SCOPE);
            const clientData = clientDataB64Std(challengeB64url, holderPubB64url);
            const blob = await AppAttest.attestKey(clientData, WIA_ATTEST_SCOPE);
            return { key_id: keyId, attestation: blob };
        }

        // Android: a Play Integrity token whose nonce is the client-data hash.
        // Play Integrity requires a URL-safe base64 nonce string; integrityToken
        // passes it through verbatim (the legacy attestKey path decoded the
        // input and mangled raw hash bytes through UTF-8, so the mint always
        // failed and the wallet silently stayed WIA-less).
        const nonce = await clientDataHashB64url(challengeB64url, holderPubB64url);
        const blob = await AppAttest.integrityToken(nonce);
        return { integrity_token: blob };
    } catch (e) {
        console.warn('[WIA] device attestation unavailable:', e instanceof Error ? e.message : e);
        return null;
    }
}

/** base64 (standard) of the raw client data: challenge_bytes ‖ holder_pub_bytes. */
function clientDataB64Std(challengeB64url: string, holderPubB64url: string): string {
    return bytesToBase64Std(clientDataBytes(challengeB64url, holderPubB64url));
}

/** base64url (unpadded) of SHA-256(challenge_bytes ‖ holder_pub_bytes). */
async function clientDataHashB64url(
    challengeB64url: string,
    holderPubB64url: string
): Promise<string> {
    const digest = await Crypto.digest(
        Crypto.CryptoDigestAlgorithm.SHA256,
        clientDataBytes(challengeB64url, holderPubB64url)
    );
    return bytesToBase64url(new Uint8Array(digest));
}

function clientDataBytes(challengeB64url: string, holderPubB64url: string): Uint8Array<ArrayBuffer> {
    const a = base64urlToBytes(challengeB64url);
    const b = base64urlToBytes(holderPubB64url);
    const joined = new Uint8Array(a.length + b.length);
    joined.set(a, 0);
    joined.set(b, a.length);
    return joined;
}

function bytesToBase64Std(bytes: Uint8Array): string {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}
