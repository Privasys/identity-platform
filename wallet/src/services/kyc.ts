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
 * See the identity-verifier (KYC) design (receipt-based,
 * commit-and-prove) and the wallet improvement design
 *
 * NOTE: the document fields are supplied by the caller. Today that is a dev
 * stub; the NFC + biometric capture native module (Phase 2 §3.3) will feed the
 * real eMRTD chip data here without changing this interface.
 */

import * as Crypto from 'expo-crypto';

import * as SecureStore from '@/utils/storage';
import { getAttestationServerToken } from '@/services/app-attest';
import { inspectAttestation, verifyAttestation } from '@/services/attestation';
import { attributeLabel, setProfileValue } from '@/services/attributes';
import { deriveAppSub } from '@/services/did';
import { derToRawEcdsa } from '@/services/encauth';
import { useProfileStore, type ProfileAttribute, type VerificationRecord } from '@/stores/profile';
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
// container-app-identity-verifier v0.2.7 (ghcr.io/privasys/container-app-identity-verifier).
// This is the OCI image digest the enclave attests at OID 3.2; it changes only
// when the verifier image is rebuilt (not on a plain redeploy). Bump it here when
// a new verifier image is published, or override per-build with the env var.
const VERIFIER_IMAGE_DIGEST =
    process.env.EXPO_PUBLIC_KYC_VERIFIER_DIGEST ??
    '5d7de7209b70c38270316b6eacc3f40b512a6ec02d68588c327c6439555534f1';

const ATTESTATION_SERVER = 'https://as.privasys.org';
const VERIFIER_DISPLAY = 'Privasys identity verifier';

/** Canonical document fields the enclave can certify and the wallet auto-fills.
 *  All are sourced from the passport chip (DG1 MRZ; place_of_birth from DG11) and
 *  carry 'gov' assurance — the set the wallet can present for, e.g., a one-tap
 *  flight check-in. Keys match the enclave's parse_dg1 output. */
const DOCUMENT_ATTRIBUTE_KEYS = [
    'given_name', 'family_name', 'birthdate', 'nationality',
    'document_number', 'document_type', 'sex', 'issuing_state', 'doc_expiry',
    'place_of_birth', 'personal_number',
] as const;
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
    measurement: string;
    /** The signed receipt. The caller presents its gov attributes
     *  (govAttributeCandidates) for the user to choose which to import, then
     *  applies the selection (applyGovAttributes). */
    record: KycRecord;
}

/** BAC/PACE access-key fields, MRZ form (dates YYMMDD), from the enclave OCR. */
export interface DocMrzFields {
    documentNumber: string;
    dateOfBirth: string;   // YYMMDD (MRZ form) — the eMRTD chip key shape
    dateOfExpiry: string;  // YYMMDD
    isScreenshot?: boolean | null;
}

/**
 * Pre-NFC MRZ read. Forwards the data-page image to the attested enclave, which
 * OCRs it with OmniMRZ — far more reliable on the OCR-B machine-readable zone
 * than on-device OCR — and returns the BAC/PACE access-key fields, check-digit
 * validated. The wallet then unlocks the chip with this enclave-grade read.
 * Attestation is re-verified (same pin as verifyIdentity) because the raw page
 * image leaves the device. Throws if the MRZ couldn't be read clearly (HTTP 422)
 * so the caller can prompt a retake.
 */
export async function readDocumentMrz(docImageBase64: string): Promise<DocMrzFields> {
    await verifyVerifierEnclave();
    const resp = await postToVerifier<{
        document_number: string;
        date_of_birth: string;
        date_of_expiry: string;
        is_screenshot?: boolean | null;
    }>('/read-mrz', { doc_image: docImageBase64 });
    return {
        documentNumber: resp.document_number,
        dateOfBirth: resp.date_of_birth,
        dateOfExpiry: resp.date_of_expiry,
        isScreenshot: resp.is_screenshot,
    };
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
    let res: { status: number; body: string };
    try {
        res = await NativeRaTls.post(host, port, path, JSON.stringify(body));
    } catch (e: any) {
        // A frozen (unconfigured) verifier answers a large body (e.g. the selfie)
        // with a 503 but closes before draining the request, so the client sees a
        // broken pipe / connection reset rather than the 503. Surface the same
        // actionable message instead of a raw socket error.
        const msg = String(e?.message ?? e);
        if (/broken pipe|connection reset|connection closed|os error 32|reset by peer/i.test(msg)) {
            throw new Error('The identity verifier is unavailable or awaiting configuration (trust anchors). Try again shortly.');
        }
        throw e;
    }
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
 * @param opts.liveImageBase64 Optional live selfie for the enclave face match +
 *   liveness (DG2 ↔ live capture). Processed in-enclave, never persisted.
 */
export async function verifyIdentity(
    doc: {
        fields: Record<string, string>;
        /** EF.SOD (base64) — required by the enclave for Passive Authentication. */
        sod?: string;
        /** Raw data groups keyed by DG number ("1", "2"), base64. */
        dataGroups?: Record<string, string>;
    },
    opts: { liveImageBase64?: string; docImage?: string } = {},
): Promise<VerifyIdentityResult> {
    const enclave = await verifyVerifierEnclave();
    const holderPub = await getHolderPublicKey();

    const resp = await postToVerifier<{ ivr: string; salts: Record<string, string>; fields: Record<string, string> }>(
        '/verify-identity',
        {
            holder_pub: holderPub,
            fields: doc.fields,
            // The enclave certifies from the raw chip bytes (SOD + DGs); it runs
            // Passive Authentication against the configured CSCA trust anchors and
            // the DG2↔selfie face match in-enclave. `fields` is only a convenience.
            ...(doc.sod ? { sod: doc.sod } : {}),
            ...(doc.dataGroups ? { data_groups: doc.dataGroups } : {}),
            ...(opts.liveImageBase64 ? { live_image: opts.liveImageBase64 } : {}),
            // Data-page image → the enclave runs the heavy OCR (VIZ + MRZ) and
            // cross-references it against the chip to detect a tampered document
            // (GPG45 box 3), keeping the wallet thin. The enclave treats the chip
            // as authoritative; box 3 is skipped if no image is sent.
            ...(opts.docImage ? { doc_image: opts.docImage } : {}),
        },
    );

    const jti = decodeJwtId(resp.ivr);
    const record: KycRecord = {
        jti,
        ivr: resp.ivr,
        salts: resp.salts ?? {},
        fields: resp.fields ?? doc.fields,
        measurement: enclave.measurement,
        imageRef: enclave.imageRef,
        verifiedAt: Math.floor(Date.now() / 1000),
    };
    await saveKycRecord(record);

    return { jti, measurement: enclave.measurement, record };
}

// The legal names from the document go to dedicated *_id attributes — never
// overwrite the holder's preferred everyday name (e.g. "Bertrand" vs the
// passport's legal "BERTRAND FRANCOIS"). The wallet then *asks* whether to adopt
// the ID name (see kyc-capture). Other fields store under their own key.
const GOV_STORE_KEY: Record<string, string> = {
    given_name: 'given_name_id',
    family_name: 'family_name_id',
};

function govRecord(record: KycRecord, evidence: string): VerificationRecord {
    return {
        verifier: 'privasys-kyc',
        verifierDisplayName: VERIFIER_DISPLAY,
        method: 'kyc_enclave',
        assurance: 'gov',
        verifiedAt: record.verifiedAt,
        evidence,
    };
}

/** Image data-URI for the DG2 portrait (raw base64 from the chip). */
function portraitDataUri(b64: string): string {
    return b64.startsWith('data:') ? b64 : `data:image/jpeg;base64,${b64}`;
}

/**
 * The gov-certified attributes a verified record offers, as display rows for the
 * import-selection sheet (so the user chooses what to import, like the IdP import
 * flow). Includes age_over_N booleans derived from the certified DOB and, when
 * supplied, the ID portrait as `picture_id` (Photo (ID)).
 */
export function govAttributeCandidates(record: KycRecord, portraitBase64?: string): ProfileAttribute[] {
    const out: ProfileAttribute[] = [];
    const push = (key: string, value: string) =>
        out.push({ key, label: attributeLabel(key), value, source: 'document', verified: true });

    for (const key of DOCUMENT_ATTRIBUTE_KEYS) {
        const value = record.fields[key];
        if (value) push(GOV_STORE_KEY[key] ?? key, value);
    }
    // age_over_N: privacy-preserving boolean derived from the gov-verified DOB.
    const birthdate = record.fields.birthdate;
    if (birthdate) {
        const age = ageFromBirthdate(birthdate);
        if (age != null) for (const t of AGE_THRESHOLDS) push(`age_over_${t}`, age >= t ? 'true' : 'false');
    }
    if (portraitBase64) push('picture_id', portraitDataUri(portraitBase64));
    return out;
}

/** Apply the user-selected gov attributes to the profile at gov assurance. */
export function applyGovAttributes(
    record: KycRecord,
    selected: Set<string>,
    portraitBase64?: string,
): string[] {
    const store = useProfileStore.getState();
    const filled: string[] = [];
    for (const attr of govAttributeCandidates(record, portraitBase64)) {
        if (!selected.has(attr.key)) continue;
        const evidence = attr.key.startsWith('age_over_')
            ? `ivr:${record.jti}#${attr.key}`
            : `ivr:${record.jti}`;
        setProfileValue(store, attr.key, attr.value, 'document', {
            verified: true,
            verifications: [govRecord(record, evidence)],
        });
        filled.push(attr.key);
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

// ── Disclosure derivations (prove_*) ────────────────────────────────────────
//
// At relay time the wallet derives a short-lived, audience-bound, enclave-signed
// disclosure token for exactly the one claim a relying party asked for, opening
// only that commitment — the raw value never leaves the wallet. Each request is
// holder-signed (the IVR is bound to the holder key) and consented.

function b64uBytes(bytes: Uint8Array): string {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i] ?? 0);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uToBytes(s: string): Uint8Array {
    const std = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
    const bin = atob(std);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

/** Canonical JSON matching the verifier's crypto.canonical_json: sorted keys,
 *  compact separators (",",":"), no whitespace. Values here are ASCII strings
 *  + one integer, so JS and Python serialise identically. */
function canonicalJson(obj: Record<string, string | number>): string {
    const keys = Object.keys(obj).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + JSON.stringify(obj[k])).join(',') + '}';
}

interface SignedBase {
    ivr: string;
    sub: string;
    rp_id: string;
    nonce: string;
    ts: number;
    holder_pub: string;
    holder_sig: string;
}

/** Holder-sign canonical_json({ivr,nonce,rp_id,ts}) with the hardware key,
 *  returning base64url(64-byte raw R‖S) as the verifier expects. */
async function holderSignature(jti: string, rpId: string, nonce: string, ts: number): Promise<string> {
    const msg = new TextEncoder().encode(canonicalJson({ ivr: jti, nonce, rp_id: rpId, ts }));
    const { signature } = await NativeKeys.sign(HOLDER_KEY_ID, b64uBytes(msg));
    const raw = derToRawEcdsa(b64uToBytes(signature));
    if (raw.length !== 64) throw new Error('holder_sig must be 64 bytes');
    return b64uBytes(raw);
}

async function buildSignedBase(record: KycRecord, rpId: string, nonce?: string): Promise<SignedBase> {
    const profile = useProfileStore.getState().profile;
    if (!profile?.pairwiseSeed) throw new Error('Profile is not initialised');
    const sub = await deriveAppSub(profile.pairwiseSeed, rpId);
    const n = nonce ?? b64uBytes(Crypto.getRandomBytes(16));
    const ts = Math.floor(Date.now() / 1000);
    const holderPub = await getHolderPublicKey();
    const holderSig = await holderSignature(record.jti, rpId, n, ts);
    return { ivr: record.ivr, sub, rp_id: rpId, nonce: n, ts, holder_pub: holderPub, holder_sig: holderSig };
}

async function requireRecord(): Promise<KycRecord> {
    const record = await getLatestKycRecord();
    if (!record) throw new Error('No verified identity on file — verify your ID first.');
    return record;
}

/** prove_age_over: signed "age_over_N = yes/no" without revealing the birth date. */
export async function proveAgeOver(rpId: string, threshold: number, nonce?: string): Promise<string> {
    const record = await requireRecord();
    const base = await buildSignedBase(record, rpId, nonce);
    const resp = await postToVerifier<{ token: string }>('/prove/age-over', {
        ...base,
        birthdate: record.fields.birthdate,
        salt: record.salts.birthdate,
        threshold,
    });
    return resp.token;
}

/** prove_age_band: signed age band (e.g. "18-20") instead of a threshold. */
export async function proveAgeBand(rpId: string, bands?: number[], nonce?: string): Promise<string> {
    const record = await requireRecord();
    const base = await buildSignedBase(record, rpId, nonce);
    const resp = await postToVerifier<{ token: string }>('/prove/age-band', {
        ...base,
        birthdate: record.fields.birthdate,
        salt: record.salts.birthdate,
        ...(bands ? { bands } : {}),
    });
    return resp.token;
}

/** prove_field: signed disclosure of one certified document field. */
export async function proveField(rpId: string, field: string, nonce?: string): Promise<string> {
    const record = await requireRecord();
    const value = record.fields[field];
    const salt = record.salts[field];
    if (value == null || salt == null) {
        throw new Error(`No verified value for "${field}" in the identity receipt.`);
    }
    const base = await buildSignedBase(record, rpId, nonce);
    const resp = await postToVerifier<{ token: string }>('/prove/field', { ...base, field, value, salt });
    return resp.token;
}

/** prove_document_valid: signed assertion that a genuine document was verified,
 *  disclosing no attribute. */
export async function proveDocumentValid(rpId: string, nonce?: string): Promise<string> {
    const record = await requireRecord();
    const base = await buildSignedBase(record, rpId, nonce);
    const resp = await postToVerifier<{ token: string }>('/prove/document-valid', base);
    return resp.token;
}

/**
 * Produce the right disclosure token for a requested gov-assurance attribute.
 * `age_over_N` → prove_age_over; `age_band` → prove_age_band; any certified
 * field (birthdate, nationality, given_name, family_name) → prove_field.
 */
export async function discloseAttribute(rpId: string, key: string, nonce?: string): Promise<string> {
    const ageOver = /^age_over_(\d+)$/.exec(key);
    if (ageOver) return proveAgeOver(rpId, Number(ageOver[1]), nonce);
    if (key === 'age_band') return proveAgeBand(rpId, undefined, nonce);
    return proveField(rpId, key, nonce);
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
