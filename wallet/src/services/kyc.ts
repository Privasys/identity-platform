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

import { getAttestationServerToken } from '@/services/app-attest';
import {
    inspectAttestation,
    attestEnclave,
    type AttestationResult
} from '@/services/attestation';
import { useSettingsStore } from '@/stores/settings';
import { attributeLabel, setProfileValue } from '@/services/attributes';
import { deriveAppSub } from '@/services/did';
import { derToRawEcdsa } from '@/services/encauth';
import { useProfileStore, type ProfileAttribute, type VerificationRecord } from '@/stores/profile';
import {
    bytesToBase64url as b64uBytes,
    base64urlToBytes as b64uToBytes,
    canonicalJson
} from '@/utils/encoding';
import * as SecureStore from '@/utils/storage';

import * as NativeKeys from '../../modules/native-keys/src/index';
import * as NativeRaTls from '../../modules/native-ratls/src/index';
import { ensureWia, getValidWia } from './wia';

/** Hardware-bound holder key; the IVR binds to it and prove_* requests are
 *  signed by it. Same key the wallet uses for its DID / FIDO2 signing. */
const HOLDER_KEY_ID = 'privasys-wallet-default';

/** Sealed storage key for the KYC receipt record(s). */
const KYC_STORE_KEY = 'privasys.kyc.records';

/** Platform (management-service) API base. The wallet resolves the verifier app
 *  by name from the app store, so its origin + pinned image digest are NOT baked
 *  into the build. Defaults to the test platform (matching the dev verifier
 *  fallback below); set EXPO_PUBLIC_PLATFORM_API_URL for prod. */
const PLATFORM_API_BASE =
    process.env.EXPO_PUBLIC_PLATFORM_API_URL ?? 'https://api-test.developer.privasys.org';

/** Store name of the identity-verifier app to resolve. */
const VERIFIER_APP_NAME =
    process.env.EXPO_PUBLIC_KYC_VERIFIER_APP ?? 'container-app-identity-verifier';

/** Attestation extension carrying the workload image digest (org.privasys,
 *  1.3.6.1.4.1.65230.3.2). Pinning this is what makes "send my passport to the
 *  enclave" safe: we only talk to the published, auditable code. The resolve API
 *  returns this too; this is the default. */
const VERIFIER_IMAGE_OID = '1.3.6.1.4.1.65230.3.2';

/** Fallback verifier coordinates, used only until the app is resolvable from the
 *  store (then the resolved hostname + attested digest win). Defaults are the dev
 *  TDX deployment; both overridable per build.
 *  container-app-identity-verifier v0.3.11: fail-closed biometrics — verify-identity
 *  denies on a face mismatch; liveness PAD (MiniFASNetV2) enforced. Keep this pinned
 *  to the live test deployment's image digest (OID 3.2) so the fallback attests the
 *  current enclave when the resolve API is unreachable. */
const FALLBACK_VERIFIER_ORIGIN =
    process.env.EXPO_PUBLIC_KYC_VERIFIER_ORIGIN ??
    'container-app-identity-verifier.apps-test.privasys.org';
const FALLBACK_VERIFIER_IMAGE_DIGEST =
    process.env.EXPO_PUBLIC_KYC_VERIFIER_DIGEST ??
    'aa922a94d6f8ef6765c2e930ae31bf63025c69958da6bfbe078d221bde1fa01f';

const ATTESTATION_SERVER = 'https://as.privasys.org';
const VERIFIER_DISPLAY = 'Privasys identity verifier';

/** Resolved verifier coordinates (origin + the image digest to pin), fetched
 *  once from the platform store and cached for the session. */
interface ResolvedVerifier {
    origin: string;
    imageOid: string;
    imageDigest: string;
}
let resolvedVerifier: ResolvedVerifier | null = null;

/**
 * Resolve the identity-verifier's deployment from the app store by name: its
 * hostname and the attested image digest to pin (OID 3.2). This replaces the
 * hard-coded origin + digest. The values are still only *hints*: verifyVerifierEnclave
 * re-verifies the enclave's RA-TLS attestation against as.privasys.org and pins
 * the digest against the certificate, so the resolve channel cannot direct the
 * wallet to an un-attested enclave. Falls back to the build defaults if the app
 * is not yet in the store or the platform is unreachable.
 */
async function resolveVerifier(): Promise<ResolvedVerifier> {
    if (resolvedVerifier) return resolvedVerifier;
    try {
        const res = await fetch(
            `${PLATFORM_API_BASE}/api/v1/apps/by-name/${encodeURIComponent(VERIFIER_APP_NAME)}/resolve`
        );
        if (res.ok) {
            const j = (await res.json()) as {
                hostname?: string;
                image_oid?: string;
                image_digest?: string;
            };
            if (j.hostname && j.image_digest) {
                resolvedVerifier = {
                    origin: j.hostname,
                    imageOid: j.image_oid || VERIFIER_IMAGE_OID,
                    imageDigest: j.image_digest.toLowerCase()
                };
                return resolvedVerifier;
            }
        }
    } catch {
        // fall through to the build fallback
    }
    resolvedVerifier = {
        origin: FALLBACK_VERIFIER_ORIGIN,
        imageOid: VERIFIER_IMAGE_OID,
        imageDigest: FALLBACK_VERIFIER_IMAGE_DIGEST
    };
    return resolvedVerifier;
}

/** Canonical document fields the enclave can certify and the wallet auto-fills.
 *  All are sourced from the passport chip (DG1 MRZ; place_of_birth from DG11) and
 *  carry 'gov' assurance — the set the wallet can present for, e.g., a one-tap
 *  flight check-in. Keys match the enclave's parse_dg1 output. */
const DOCUMENT_ATTRIBUTE_KEYS = [
    'given_name',
    'family_name',
    'birthdate',
    'nationality',
    'document_number',
    'document_type',
    'sex',
    'issuing_state',
    'doc_expiry',
    'place_of_birth',
    'personal_number'
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
    /** Raw DG2 data group (standard base64, exactly as sent to the enclave).
     *  Kept so /prove/presence can re-open the IVR's portrait commitment and
     *  the enclave can match a FRESH selfie against this document's photo.
     *  Absent on records that predate presence support (re-verify to enable). */
    dg2?: string;
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
    dateOfBirth: string; // YYMMDD (MRZ form) — the eMRTD chip key shape
    dateOfExpiry: string; // YYMMDD
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
        isScreenshot: resp.is_screenshot
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

export interface VerifierAttestation {
    /** RA-TLS origin (hostname) the wallet attested. */
    origin: string;
    /** Human-readable name for the "Verify Enclave" header. */
    displayName: string;
    /** Full attestation result to render in the shared AttestationView. */
    attestation: AttestationResult;
}

/**
 * Attest the verifier enclave: resolve it, inspect the RA-TLS cert, pin the
 * published image digest at the Identity image OID, then verify against the
 * attestation server. This is the single source of truth for "is this the
 * genuine, published identity-verifier?" — used both to gate sending any
 * document data and to render the user-facing "Verify Enclave" screen (the same
 * view shown at sign-in). Throws on a missing/mismatched digest or a failed
 * verification, so the wallet never trusts an unexpected enclave.
 */
export async function attestVerifier(): Promise<VerifierAttestation> {
    const v = await resolveVerifier();
    const inspected = await inspectAttestation(v.origin);

    const oid = inspected.custom_oids?.find((o) => o.oid === v.imageOid);
    if (!oid) {
        throw new Error(
            'verifier attestation is missing the identity image OID — refusing to send identity data'
        );
    }
    if (oid.value_hex.toLowerCase() !== v.imageDigest.toLowerCase()) {
        throw new Error(
            'verifier image digest does not match the expected published build — refusing to proceed'
        );
    }

    const asToken = await getAttestationServerToken();
    // Verify in the user's default mode (deterministic unless they opted into
    // challenge) and always through the attestation service. Throws on a
    // non-verified outcome so identity data is never sent to an enclave that
    // could not prove itself.
    const mode = useSettingsStore.getState().verificationMode;
    const outcome = await attestEnclave(v.origin, {
        tee: inspected.tee_type ?? 'tdx',
        mode,
        attestationServer: ATTESTATION_SERVER,
        attestationServerToken: asToken
    });
    if (outcome.status !== 'verified' || !outcome.result) {
        throw new Error(
            `verifier attestation ${outcome.status}${outcome.message ? `: ${outcome.message}` : ''}`
        );
    }
    const verified = outcome.result;

    // Rich display fields (cert, extensions) from inspect; authoritative validity,
    // measurements and image ref from the verified result.
    const attestation: AttestationResult = {
        ...inspected,
        valid: verified.valid,
        mrtd: verified.mrtd ?? inspected.mrtd,
        mrenclave: verified.mrenclave ?? inspected.mrenclave,
        workload_image_ref: verified.workload_image_ref ?? inspected.workload_image_ref,
        quote_verification_status:
            verified.quote_verification_status ?? inspected.quote_verification_status
    };
    return { origin: v.origin, displayName: VERIFIER_DISPLAY, attestation };
}

/**
 * Resolved verifier identity for display (origin + name) WITHOUT attesting — so
 * the consent screen can name the app + show its origin before the user agrees,
 * deferring the actual RA-TLS verification to the dedicated enclave page.
 */
export async function getVerifierInfo(): Promise<{ origin: string; displayName: string }> {
    const v = await resolveVerifier();
    return { origin: v.origin, displayName: VERIFIER_DISPLAY };
}

/**
 * The measurement + image ref of the attested verifier, for stamping into the
 * KycRecord. A thin derivation of attestVerifier() so the attestation logic
 * lives in exactly one place.
 */
async function verifyVerifierEnclave(): Promise<VerifierIdentity> {
    const { attestation } = await attestVerifier();
    return {
        measurement: attestation.mrtd ?? attestation.mrenclave ?? '',
        imageRef: attestation.workload_image_ref
    };
}

async function postToVerifier<T>(path: string, body: unknown, voucher?: string): Promise<T> {
    const { origin } = await resolveVerifier();
    const url = new URL(`https://${origin}`);
    const host = url.hostname;
    const port = parseInt(url.port || '443', 10);
    // Attach the (cached, non-prompting) Wallet Instance Attestation to the
    // WIA-gated endpoints so the enclave can prove this is our wallet before
    // doing free identity work. Omitted when none is cached — the enclave gate
    // is fail-open during rollout (IDENTITY_VERIFIER_REQUIRE_WIA).
    let finalBody = body;
    if (
        (path === '/verify-identity' || path.startsWith('/prove/')) &&
        body &&
        typeof body === 'object'
    ) {
        const wia = await getValidWia();
        if (wia) finalBody = { ...(body as Record<string, unknown>), wia };
    }
    // A paid disclosure carries the relying party's voucher on a header the
    // enclave runtime verifies (and meters) before the verifier app sees the
    // request. Free proofs (a self-audience check) carry none.
    const headers = voucher ? { 'X-Privasys-Voucher': voucher } : undefined;
    let res: { status: number; body: string };
    try {
        res = await NativeRaTls.post(host, port, path, JSON.stringify(finalBody), headers);
    } catch (e: any) {
        // A frozen (unconfigured) verifier answers a large body (e.g. the selfie)
        // with a 503 but closes before draining the request, so the client sees a
        // broken pipe / connection reset rather than the 503. Surface the same
        // actionable message instead of a raw socket error.
        const msg = String(e?.message ?? e);
        if (/broken pipe|connection reset|connection closed|os error 32|reset by peer/i.test(msg)) {
            throw new Error(
                'The identity verifier is unavailable or awaiting configuration (trust anchors). Try again shortly.'
            );
        }
        throw e;
    }
    if (res.status === 503) {
        throw new Error(
            'The identity verifier is not yet configured (trust anchors pending). Try again shortly.'
        );
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
        /** Raw data groups keyed by DG number ("1", "2", "15"), base64. */
        dataGroups?: Record<string, string>;
        /** Active Authentication relay (present iff the chip carries DG15): the
         *  reader's per-read challenge + the chip's signature, base64url. The
         *  enclave re-verifies it against DG15 to prove the chip is not a clone. */
        aa?: { challenge: string; signature: string; passed?: boolean };
    },
    opts: { liveImageBase64?: string; docImage?: string } = {}
): Promise<VerifyIdentityResult> {
    const enclave = await verifyVerifierEnclave();
    const holderPub = await getHolderPublicKey();

    // Enrol (or refresh) the Wallet Instance Attestation now — inside the KYC
    // flow, where a biometric is expected — so it is cached for this request and
    // the follow-up prove_* derivations. Best-effort: a failure leaves the wallet
    // WIA-less and verification proceeds (the enclave gate is fail-open until the
    // fleet enforces it).
    await ensureWia().catch(() => undefined);

    const resp = await postToVerifier<{
        ivr: string;
        salts: Record<string, string>;
        fields: Record<string, string>;
    }>('/verify-identity', {
        holder_pub: holderPub,
        fields: doc.fields,
        // The enclave certifies from the raw chip bytes (SOD + DGs); it runs
        // Passive Authentication against the configured CSCA trust anchors and
        // the DG2↔selfie face match in-enclave. `fields` is only a convenience.
        ...(doc.sod ? { sod: doc.sod } : {}),
        ...(doc.dataGroups ? { data_groups: doc.dataGroups } : {}),
        // Active Authentication (anti-clone): forward the chip's signature over
        // its per-read challenge. The enclave requires this when DG15 is
        // present (in data_groups) and re-verifies it against the chip's key.
        ...(doc.aa ? { aa: { challenge: doc.aa.challenge, signature: doc.aa.signature } } : {}),
        ...(opts.liveImageBase64 ? { live_image: opts.liveImageBase64 } : {}),
        // Data-page image → the enclave runs the heavy OCR (VIZ + MRZ) and
        // cross-references it against the chip to detect a tampered document
        // (GPG45 box 3), keeping the wallet thin. The enclave treats the chip
        // as authoritative; box 3 is skipped if no image is sent.
        ...(opts.docImage ? { doc_image: opts.docImage } : {})
    });

    const jti = decodeJwtId(resp.ivr);
    const record: KycRecord = {
        jti,
        ivr: resp.ivr,
        salts: resp.salts ?? {},
        fields: resp.fields ?? doc.fields,
        measurement: enclave.measurement,
        imageRef: enclave.imageRef,
        verifiedAt: Math.floor(Date.now() / 1000),
        // Keep the DG2 the enclave committed to (salts.picture_dg2), so a
        // later /prove/presence can re-open the portrait commitment.
        ...(doc.dataGroups?.['2'] ? { dg2: doc.dataGroups['2'] } : {})
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
    family_name: 'family_name_id'
};

function govRecord(record: KycRecord, evidence: string): VerificationRecord {
    return {
        verifier: 'privasys-kyc',
        verifierDisplayName: VERIFIER_DISPLAY,
        method: 'kyc_enclave',
        assurance: 'gov',
        verifiedAt: record.verifiedAt,
        evidence
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
export function govAttributeCandidates(
    record: KycRecord,
    portraitBase64?: string
): ProfileAttribute[] {
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
        if (age != null)
            for (const t of AGE_THRESHOLDS) push(`age_over_${t}`, age >= t ? 'true' : 'false');
    }
    if (portraitBase64) push('picture_id', portraitDataUri(portraitBase64));
    return out;
}

/** Apply the user-selected gov attributes to the profile at gov assurance. */
export function applyGovAttributes(
    record: KycRecord,
    selected: Set<string>,
    portraitBase64?: string
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
            verifications: [govRecord(record, evidence)]
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
async function holderSignature(
    jti: string,
    rpId: string,
    nonce: string,
    ts: number
): Promise<string> {
    const msg = new TextEncoder().encode(canonicalJson({ ivr: jti, nonce, rp_id: rpId, ts }));
    const { signature } = await NativeKeys.sign(HOLDER_KEY_ID, b64uBytes(msg));
    const raw = derToRawEcdsa(b64uToBytes(signature));
    if (raw.length !== 64) throw new Error('holder_sig must be 64 bytes');
    return b64uBytes(raw);
}

async function buildSignedBase(
    record: KycRecord,
    rpId: string,
    nonce?: string
): Promise<SignedBase> {
    const profile = useProfileStore.getState().profile;
    if (!profile?.pairwiseSeed) throw new Error('Profile is not initialised');
    const sub = await deriveAppSub(profile.pairwiseSeed, rpId);
    const n = nonce ?? b64uBytes(Crypto.getRandomBytes(16));
    const ts = Math.floor(Date.now() / 1000);
    const holderPub = await getHolderPublicKey();
    const holderSig = await holderSignature(record.jti, rpId, n, ts);
    return {
        ivr: record.ivr,
        sub,
        rp_id: rpId,
        nonce: n,
        ts,
        holder_pub: holderPub,
        holder_sig: holderSig
    };
}

async function requireRecord(): Promise<KycRecord> {
    const record = await getLatestKycRecord();
    if (!record) throw new Error('No verified identity on file — verify your ID first.');
    return record;
}

/** prove_age_over: signed "age_over_N = yes/no" without revealing the birth date. */
export async function proveAgeOver(
    rpId: string,
    threshold: number,
    nonce?: string,
    voucher?: string
): Promise<string> {
    const record = await requireRecord();
    const base = await buildSignedBase(record, rpId, nonce);
    const resp = await postToVerifier<{ token: string }>('/prove/age-over', {
        ...base,
        birthdate: record.fields.birthdate,
        salt: record.salts.birthdate,
        threshold
    }, voucher);
    return resp.token;
}

/** prove_age_band: signed age band (e.g. "18-20") instead of a threshold. */
export async function proveAgeBand(
    rpId: string,
    bands?: number[],
    nonce?: string,
    voucher?: string
): Promise<string> {
    const record = await requireRecord();
    const base = await buildSignedBase(record, rpId, nonce);
    const resp = await postToVerifier<{ token: string }>('/prove/age-band', {
        ...base,
        birthdate: record.fields.birthdate,
        salt: record.salts.birthdate,
        ...(bands ? { bands } : {})
    }, voucher);
    return resp.token;
}

/** prove_field: signed disclosure of one certified document field. */
export async function proveField(
    rpId: string,
    field: string,
    nonce?: string,
    voucher?: string
): Promise<string> {
    const record = await requireRecord();
    const value = record.fields[field];
    const salt = record.salts[field];
    if (value == null || salt == null) {
        throw new Error(`No verified value for "${field}" in the identity receipt.`);
    }
    const base = await buildSignedBase(record, rpId, nonce);
    const resp = await postToVerifier<{ token: string }>('/prove/field', {
        ...base,
        field,
        value,
        salt
    }, voucher);
    return resp.token;
}

/** Salt key of the IVR's DG2 portrait commitment (mirrors the verifier). */
export const PORTRAIT_SALT_KEY = 'picture_dg2';

/** Whether the latest identity receipt can do a fresh-presence check
 *  (needs the DG2 portrait + its commitment salt — both present only on
 *  records minted by verifier >= 0.5.0 with the chip photo). */
export async function presenceAvailable(): Promise<boolean> {
    const record = await getLatestKycRecord();
    return !!(record?.dg2 && record.salts[PORTRAIT_SALT_KEY]);
}

/** prove_presence: fresh selfie matched in-enclave against the document
 *  portrait this IVR committed to. Proves the DOCUMENT HOLDER is present now —
 *  device biometrics only prove someone enrolled on the phone. The selfie and
 *  portrait are processed in the enclave and discarded; a non-match is a hard
 *  error (the enclave never mints a negative). */
export async function provePresence(
    rpId: string,
    selfieBase64: string,
    nonce?: string,
    voucher?: string
): Promise<string> {
    const record = await requireRecord();
    if (!record.dg2 || !record.salts[PORTRAIT_SALT_KEY]) {
        throw new Error(
            'This identity receipt predates presence support — re-verify your ID to enable it.'
        );
    }
    const base = await buildSignedBase(record, rpId, nonce);
    const resp = await postToVerifier<{ token: string }>('/prove/presence', {
        ...base,
        // The commitment is over b64url(DG2 bytes); re-derive the exact string
        // from the stored standard-base64 copy.
        dg2: b64uBytes(b64uToBytes(record.dg2)),
        salt: record.salts[PORTRAIT_SALT_KEY],
        selfie: selfieBase64
    }, voucher);
    return resp.token;
}

/** prove_document_valid: signed assertion that a genuine document was verified,
 *  disclosing no attribute. */
export async function proveDocumentValid(
    rpId: string,
    nonce?: string,
    voucher?: string
): Promise<string> {
    const record = await requireRecord();
    const base = await buildSignedBase(record, rpId, nonce);
    const resp = await postToVerifier<{ token: string }>('/prove/document-valid', base, voucher);
    return resp.token;
}

/** A paid-disclosure voucher the IdP minted for the relying party (from the
 *  authorize/device payload's `disclosureVouchers`). `claims` lists the
 *  marketplace attribute keys it authorises, e.g. `privasys:age_over_18`. */
export interface DisclosureVoucher {
    token: string;
    provider_namespace?: string;
    issuer_url?: string;
    issuing_app_id?: string;
    claims: string[];
}

/** The marketplace attribute key a requested gov attribute discloses as, in the
 *  provider-namespaced form the voucher authorises (mirrors the verifier). */
export function marketplaceKey(key: string): string {
    return `privasys:${key}`;
}

/** Pick the voucher that authorises `key` (its `claims` cover the marketplace
 *  key), or undefined when none was minted for it (a free/self-audience proof). */
export function voucherForAttribute(
    key: string,
    vouchers?: DisclosureVoucher[]
): string | undefined {
    if (!vouchers?.length) return undefined;
    const mk = marketplaceKey(key);
    return vouchers.find((v) => v.claims?.includes(mk))?.token;
}

/**
 * Produce the right disclosure token for a requested gov-assurance attribute.
 * `age_over_N` → prove_age_over; `age_band` → prove_age_band; any certified
 * field (birthdate, nationality, given_name, family_name) → prove_field. When
 * the relying party's `disclosureVouchers` cover the attribute, the matching
 * voucher rides the request so the enclave meters the paid disclosure.
 */
export async function discloseAttribute(
    rpId: string,
    key: string,
    nonce?: string,
    vouchers?: DisclosureVoucher[]
): Promise<string> {
    const voucher = voucherForAttribute(key, vouchers);
    const ageOver = /^age_over_(\d+)$/.exec(key);
    if (ageOver) return proveAgeOver(rpId, Number(ageOver[1]), nonce, voucher);
    if (key === 'age_band') return proveAgeBand(rpId, undefined, nonce, voucher);
    if (key === 'holder_present') {
        // Presence needs a live selfie ceremony — the connect flow captures it
        // and calls provePresence directly; it can never resolve as a field.
        throw new Error('holder_present requires a live selfie — use provePresence');
    }
    return proveField(rpId, key, nonce, voucher);
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
