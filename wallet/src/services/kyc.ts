// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * KYC verification service — wallet ↔ identity-verifier enclave.
 *
 * The wallet holds the raw document/biometric data; it forwards it to the
 * attested verifier enclave **only to derive** a signed Identity Verification
 * Receipt (IVR), after verifying the enclave's RA-TLS attestation first (the
 * same trust the connect flow establishes for sign-in). The enclave keeps
 * nothing; the wallet stores the IVR + per-field salts (sealed) so it can later
 * derive consented disclosure tokens (prove_*), and auto-fills its profile with
 * the verified, gov-assurance attributes.
 *
 * See .operations/identity-platform/kyc-enclave-design.md (receipt-based,
 * commit-and-prove) and wallet-improve-plan.md §3.
 *
 * NOTE: the document fields are supplied by the caller. Today that is a dev
 * stub; the NFC + biometric capture native module (Phase 2 §3.3) will feed the
 * real eMRTD chip data here without changing this interface.
 */

import * as SecureStore from '@/utils/storage';
import { getAttestationServerToken } from '@/services/app-attest';
import { inspectAttestation, verifyAttestation } from '@/services/attestation';
import { setProfileValue } from '@/services/attributes';
import { useProfileStore, type VerificationRecord } from '@/stores/profile';
import * as NativeKeys from '../../modules/native-keys/src/index';
import * as NativeRaTls from '../../modules/native-ratls/src/index';

/** Hardware-bound holder key; the IVR binds to it and prove_* requests are
 *  signed by it. Same key the wallet uses for its DID / FIDO2 signing. */
const HOLDER_KEY_ID = 'privasys-wallet-default';

/** Sealed storage key for the KYC receipt record(s). */
const KYC_STORE_KEY = 'privasys.kyc.records';

/** Verifier enclave. Overridable per build; defaults to the dev TDX deployment.
 *  Prod should resolve this from the app registry + a pinned attestation policy. */
const VERIFIER_ORIGIN =
    process.env.EXPO_PUBLIC_KYC_VERIFIER_ORIGIN ?? 'identity-verifier.apps-test.privasys.org';

/** Published identity-verifier image digest, attested at the Identity image OID
 *  (org.privasys, 1.3.6.1.4.1.65230.3.2). Pinning this is what makes "send my
 *  passport to the enclave" safe: we only talk to the published, auditable code. */
const VERIFIER_IMAGE_OID = '1.3.6.1.4.1.65230.3.2';
const VERIFIER_IMAGE_DIGEST =
    process.env.EXPO_PUBLIC_KYC_VERIFIER_DIGEST ??
    'b2aa97238adce096fc0cc0a2f724b43219f7594575e59d2b4f7cad81fd409514';

const ATTESTATION_SERVER = 'https://as.privasys.org';
const VERIFIER_DISPLAY = 'Privasys identity verifier';

/** Canonical document fields the enclave can certify and the wallet auto-fills. */
const DOCUMENT_ATTRIBUTE_KEYS = ['given_name', 'family_name', 'birthdate', 'nationality'] as const;
/** Age thresholds derived locally from the gov-verified birth date. */
const AGE_THRESHOLDS = [18, 21] as const;

/** A stored identity-verification receipt. The salts + raw fields are sensitive
 *  (together they open the commitments) and live only in sealed storage. */
export interface KycRecord {
    /** IVR JWS id (jti). */
    jti: string;
    /** The signed Identity Verification Receipt (compact JWS). */
    ivr: string;
    /** Per-field salts, so prove_* can re-open exactly one commitment. */
    salts: Record<string, string>;
    /** The raw verified document fields (kept by the wallet, never re-sent). */
    fields: Record<string, string>;
    /** Enclave measurement that signed the IVR (mrtd / mrenclave). */
    measurement: string;
    /** Attested verifier image ref, if reported. */
    imageRef?: string;
    /** Epoch seconds. */
    verifiedAt: number;
}

export interface VerifyIdentityResult {
    jti: string;
    /** Profile attribute keys that were auto-filled at gov assurance. */
    filled: string[];
    measurement: string;
}

/** Holder public key (base64url SEC1 uncompressed P-256) for IVR binding. */
export async function getHolderPublicKey(): Promise<string> {
    const info = await NativeKeys.getPublicKey(HOLDER_KEY_ID);
    return info.publicKey;
}

interface VerifierIdentity {
    measurement: string;
    imageRef?: string;
}

/**
 * Verify that the enclave we are about to send identity data to is the
 * published identity-verifier, by RA-TLS attestation + pinning its image digest
 * at the Identity image OID. Throws if anything is off — we never send raw
 * document data to an unverified or unexpected enclave.
 */
async function verifyVerifierEnclave(): Promise<VerifierIdentity> {
    const inspected = await inspectAttestation(VERIFIER_ORIGIN);

    const oid = inspected.custom_oids?.find((o) => o.oid === VERIFIER_IMAGE_OID);
    if (!oid) {
        throw new Error('verifier attestation is missing the identity image OID — refusing to send identity data');
    }
    if (oid.value_hex.toLowerCase() !== VERIFIER_IMAGE_DIGEST.toLowerCase()) {
        throw new Error('verifier image digest does not match the expected published build — refusing to proceed');
    }

    const asToken = await getAttestationServerToken();
    const result = await verifyAttestation(VERIFIER_ORIGIN, {
        tee: inspected.tee_type ?? 'tdx',
        attestation_server: ATTESTATION_SERVER,
        attestation_server_token: asToken,
    });
    if (!result.valid) {
        throw new Error('verifier attestation did not verify against the attestation server');
    }
    return {
        measurement: result.mrtd ?? result.mrenclave ?? '',
        imageRef: result.workload_image_ref,
    };
}

async function postToVerifier<T>(path: string, body: unknown): Promise<T> {
    const url = new URL(`https://${VERIFIER_ORIGIN}`);
    const host = url.hostname;
    const port = parseInt(url.port || '443', 10);
    const res = await NativeRaTls.post(host, port, path, JSON.stringify(body));
    if (res.status === 503) {
        throw new Error('The identity verifier is not yet configured (trust anchors pending). Try again shortly.');
    }
    if (res.status < 200 || res.status >= 300) {
        throw new Error(`Identity verifier returned HTTP ${res.status}: ${res.body.slice(0, 200)}`);
    }
    return JSON.parse(res.body) as T;
}

/**
 * Run identity verification against the enclave and auto-fill the wallet's
 * gov-assurance attributes from the result.
 *
 * @param documentFields Parsed document fields (dev stub today; NFC chip data
 *   in production). At minimum: given_name, family_name, birthdate (YYYY-MM-DD),
 *   nationality (ISO 3166-1 alpha-3).
 */
export async function verifyIdentity(documentFields: Record<string, string>): Promise<VerifyIdentityResult> {
    const enclave = await verifyVerifierEnclave();
    const holderPub = await getHolderPublicKey();

    const resp = await postToVerifier<{ ivr: string; salts: Record<string, string>; fields: Record<string, string> }>(
        '/verify-identity',
        { holder_pub: holderPub, fields: documentFields },
    );

    const jti = decodeJwtId(resp.ivr);
    const record: KycRecord = {
        jti,
        ivr: resp.ivr,
        salts: resp.salts ?? {},
        fields: resp.fields ?? documentFields,
        measurement: enclave.measurement,
        imageRef: enclave.imageRef,
        verifiedAt: Math.floor(Date.now() / 1000),
    };
    await saveKycRecord(record);

    const filled = autofillGovAttributes(record);
    return { jti, filled, measurement: enclave.measurement };
}

/** Auto-fill the profile with gov-certified attributes from a verified record. */
function autofillGovAttributes(record: KycRecord): string[] {
    const store = useProfileStore.getState();
    const filled: string[] = [];

    const govRecord = (evidence: string): VerificationRecord => ({
        verifier: 'privasys-kyc',
        verifierDisplayName: VERIFIER_DISPLAY,
        method: 'kyc_enclave',
        assurance: 'gov',
        verifiedAt: record.verifiedAt,
        evidence,
    });

    for (const key of DOCUMENT_ATTRIBUTE_KEYS) {
        const value = record.fields[key];
        if (!value) continue;
        setProfileValue(store, key, value, 'document', {
            verified: true,
            verifications: [govRecord(`ivr:${record.jti}`)],
        });
        filled.push(key);
    }

    // age_over_N is a privacy-preserving boolean derived from the gov-verified
    // birth date; it inherits gov assurance (its source is the certified DOB).
    const birthdate = record.fields.birthdate;
    if (birthdate) {
        const age = ageFromBirthdate(birthdate);
        if (age != null) {
            for (const threshold of AGE_THRESHOLDS) {
                const key = `age_over_${threshold}`;
                setProfileValue(store, key, age >= threshold ? 'true' : 'false', 'document', {
                    verified: true,
                    verifications: [govRecord(`ivr:${record.jti}#age_over_${threshold}`)],
                });
                filled.push(key);
            }
        }
    }
    return filled;
}

/** Whole years between a YYYY-MM-DD birth date and today, or null if unparseable. */
function ageFromBirthdate(birthdate: string): number | null {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(birthdate);
    if (!m) return null;
    const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const now = new Date();
    let age = now.getFullYear() - y;
    if (now.getMonth() + 1 < mo || (now.getMonth() + 1 === mo && now.getDate() < d)) age -= 1;
    return age;
}

/** Extract the `jti` claim from a compact JWS without verifying it (the enclave
 *  already signed it; the signature is checked by relying parties / prove_*). */
function decodeJwtId(jws: string): string {
    try {
        const payload = jws.split('.')[1];
        const b64 = payload.replace(/-/g, '+').replace(/_/g, '/');
        const json = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
        return (JSON.parse(json).jti as string) ?? '';
    } catch {
        return '';
    }
}

// ── Sealed persistence ──────────────────────────────────────────────────────

export async function saveKycRecord(record: KycRecord): Promise<void> {
    const records = await loadKycRecords();
    const next = [record, ...records.filter((r) => r.jti !== record.jti)];
    await SecureStore.setItemAsync(KYC_STORE_KEY, JSON.stringify(next));
}

export async function loadKycRecords(): Promise<KycRecord[]> {
    const raw = await SecureStore.getItemAsync(KYC_STORE_KEY);
    if (!raw) return [];
    try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? (parsed as KycRecord[]) : [];
    } catch {
        return [];
    }
}

/** Most recent verification receipt, if any. */
export async function getLatestKycRecord(): Promise<KycRecord | null> {
    const records = await loadKycRecords();
    return records[0] ?? null;
}

export async function clearKycRecords(): Promise<void> {
    await SecureStore.deleteItemAsync(KYC_STORE_KEY);
}
