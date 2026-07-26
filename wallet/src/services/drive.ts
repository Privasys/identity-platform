// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Privasys Drive — the wallet's confidential personal drive.
 *
 * The wallet resolves the Drive enclave by name (mirroring kyc.ts
 * resolveVerifier), inspects its RA-TLS certificate to pin the published image
 * digest AND read its management app id (OID 3.6), then connects the
 * @privasys/drive-sdk over the RA-TLS sealed transport (makeRaTlsFetch) with a
 * platform at+jwt, and runs the one-call setupPersonalDrive (ensure tenant +
 * fetch data-key grant from mgmt + provision the tenant MEK on the enclave).
 *
 * The user approves the Drive enclave on first connect (the shared
 * AttestationView, driven from the Drive tab) and re-approves if its
 * attestation changes, mirroring the ID-check verifier flow.
 */

import { PrivasysDrive, type DriveNode, type Tenant } from '@privasys/drive-sdk';

import { getAttestationServerToken } from '@/services/app-attest';
import { inspectAttestation, attestEnclave, type AttestationResult } from '@/services/attestation';
import { appIdFromOids, OID_WORKLOAD_IMAGE_DIGEST } from '@/services/release-provenance';
import { getPlatformToken } from '@/services/platform-token';
import { useSettingsStore, type VerificationMode } from '@/stores/settings';
import { makeRaTlsFetch } from '../../modules/native-ratls/src/index';

// The management/control-plane base for Drive resolve + the data-key grant.
// Follows the build's platform (a production wallet bakes
// EXPO_PUBLIC_PLATFORM_API_URL = api.developer.privasys.org, where the prod
// `privasys-drive` app lives). EXPO_PUBLIC_DRIVE_PLATFORM_API_URL is an
// optional per-build override for pointing Drive at a different control plane.
const PLATFORM_API_BASE =
    process.env.EXPO_PUBLIC_DRIVE_PLATFORM_API_URL ??
    process.env.EXPO_PUBLIC_PLATFORM_API_URL ??
    'https://api-test.developer.privasys.org';

/** Store name of the Drive app to resolve. Prod build sets `privasys-drive`
 *  (eas.json); dev defaults to `drive-demo`. */
const DRIVE_APP_NAME = process.env.EXPO_PUBLIC_DRIVE_APP ?? 'drive-demo';

/** Fallback Drive coordinates, mirroring the identity-verifier pattern
 *  (kyc.ts resolveVerifier): used until the app resolves from the store,
 *  and whenever the resolve API is unreachable — the resolved hostname +
 *  attested digest win when available. Keep the digest pinned to the
 *  live test deployment's image (OID 3.2) so the fallback attests the
 *  current enclave. drive v0.1.22: chat conversations + Memory + graph.
 *  Both overridable per build. */
const FALLBACK_DRIVE_ORIGIN =
    process.env.EXPO_PUBLIC_DRIVE_ORIGIN ?? 'drive-demo.apps-test.privasys.org';
const FALLBACK_DRIVE_IMAGE_DIGEST =
    process.env.EXPO_PUBLIC_DRIVE_DIGEST ??
    'fcb068763a21e4e41934bd6554353026b3a96b51ba1cc9ab031f74f99b73e558';

interface ResolvedDrive {
    origin: string;
    imageOid: string;
    imageDigest: string;
}

let resolved: ResolvedDrive | null = null;

/** Resolve the Drive enclave host + the published image digest to pin,
 *  falling back to the build defaults when the app is not yet in the
 *  store or the platform is unreachable (hardcoded + fallback, same as
 *  the identity verifier). Never returns null: the fallback pins the
 *  known-good deployment and attestation still gates the connection.
 *  The management app id is NOT taken from here — it is read off the
 *  attested RA-TLS leaf (OID 3.6) in setup(). */
async function resolveDrive(): Promise<ResolvedDrive> {
    if (resolved) return resolved;
    try {
        const res = await fetch(
            `${PLATFORM_API_BASE}/api/v1/apps/by-name/${encodeURIComponent(DRIVE_APP_NAME)}/resolve`
        );
        if (res.ok) {
            const j = (await res.json()) as {
                hostname?: string;
                image_oid?: string;
                image_digest?: string;
            };
            if (j.hostname && j.image_digest) {
                resolved = {
                    origin: j.hostname,
                    imageOid: j.image_oid || OID_WORKLOAD_IMAGE_DIGEST,
                    imageDigest: j.image_digest.toLowerCase()
                };
                return resolved;
            }
        }
    } catch {
        // fall through to the build fallback
    }
    resolved = {
        origin: FALLBACK_DRIVE_ORIGIN,
        imageOid: OID_WORKLOAD_IMAGE_DIGEST,
        imageDigest: FALLBACK_DRIVE_IMAGE_DIGEST.toLowerCase()
    };
    return resolved;
}

/** The attested Drive enclave, for the approval screen (before connecting). */
export interface DriveAttestation {
    origin: string;
    displayName: string;
    /** Full attestation to render in the shared AttestationView. */
    attestation: AttestationResult;
    /** Management app id (OID 3.6) the data-key grant is keyed by. */
    appId: string;
    /** Verification mode actually used. */
    mode: VerificationMode;
    /** True when a fresh nonce + TLS channel binder were folded in. */
    challenged: boolean;
}

const DRIVE_DISPLAY = 'Privasys Drive';

// The verified attestation from the most recent attestDrive() this session, so
// setup() (the connect) reuses it instead of attesting the enclave a second time.
let lastAttest: { origin: string; appId: string } | null = null;

/**
 * Resolve + inspect + attest the Drive enclave and return the result for the
 * approval screen, WITHOUT connecting. Mirrors kyc.ts attestVerifier: pins the
 * published image digest (OID 3.2), reads the management app id (OID 3.6) off
 * the attested leaf, and verifies through the attestation service in the user's
 * mode (or a forced `challenge` when they tap "Challenge this enclave"). Throws
 * on a missing/mismatched digest or a failed verification.
 */
export async function attestDrive(forceMode?: VerificationMode): Promise<DriveAttestation> {
    const d = await resolveDrive();
    const inspected = await inspectAttestation(d.origin);
    const appId = appIdFromOids(inspected.custom_oids);
    if (!appId) throw new Error('Drive enclave attestation is missing its app id (OID 3.6)');
    if (d.imageDigest) {
        const got = inspected.custom_oids
            ?.find((o) => o.oid === d.imageOid)
            ?.value_hex?.toLowerCase();
        if (got !== d.imageDigest) {
            throw new Error('Drive enclave image digest does not match the published build');
        }
    }

    const asToken = await getAttestationServerToken();
    const mode = forceMode ?? useSettingsStore.getState().verificationMode;
    const outcome = await attestEnclave(d.origin, {
        tee: inspected.tee_type ?? 'tdx',
        mode,
        attestationServerToken: asToken
    });
    if (outcome.status !== 'verified' || !outcome.result) {
        throw new Error(
            `Drive enclave attestation ${outcome.status}${outcome.message ? `: ${outcome.message}` : ''}`
        );
    }

    // Rich display fields (cert, extensions) from inspect; authoritative
    // measurements and validity from the verified result.
    const attestation: AttestationResult = { ...inspected, ...outcome.result };
    lastAttest = { origin: d.origin, appId };
    return {
        origin: d.origin,
        displayName: DRIVE_DISPLAY,
        attestation,
        appId,
        mode: outcome.mode,
        challenged: outcome.challenged
    };
}

/** A connected drive + the caller's personal tenant, cached for the session. */
export interface DriveSession {
    drive: PrivasysDrive;
    tenant: Tenant;
    origin: string;
}

let session: DriveSession | null = null;
let inflight: Promise<DriveSession | null> | null = null;

/**
 * Connect + set up the caller's personal drive, once per session. Idempotent:
 * returns the cached session on subsequent calls. Involves a platform-token
 * mint (may require a wallet sign-in) + RA-TLS + the mgmt data-key grant, so
 * call it from a user-initiated flow. Returns null when Drive is unavailable.
 */
export async function ensureDrive(): Promise<DriveSession | null> {
    if (session) return session;
    if (inflight) return inflight;
    inflight = setup().finally(() => {
        inflight = null;
    });
    return inflight;
}

/** The current connected drive session, if setup already ran this session. */
export function currentDrive(): DriveSession | null {
    return session;
}

async function setup(): Promise<DriveSession | null> {
    const d = await resolveDrive();

    // Attestation is the gate. Reuse the result from a recent attestDrive()
    // (the Drive tab's approval screen ran it, so the user has just approved);
    // otherwise attest now, so any non-UI caller is still fully verified before
    // the user's confidential data flows over the transport. The RA-TLS data
    // plane additionally re-checks the deterministic report_data binding on
    // every request, so a swapped certificate never goes unnoticed.
    const appId =
        lastAttest && lastAttest.origin === d.origin
            ? lastAttest.appId
            : (await attestDrive()).appId;

    const token = await getPlatformToken();
    const drive = PrivasysDrive.connect({
        baseUrl: `https://${d.origin}`,
        token,
        // Route the enclave host over RA-TLS; the mgmt data-keys/grant host goes
        // over the platform fetch. The SDK sends the bearer on both legs.
        fetch: makeRaTlsFetch({ enclaveHost: d.origin, platformFetch: fetch })
    });
    const { tenant } = await drive.setupPersonalDrive({ mgmtBaseUrl: PLATFORM_API_BASE, appId });

    session = { drive, tenant, origin: d.origin };
    return session;
}

/** A share request as the drive stores it: sub + scope + status only —
 *  the presented attributes live in the wallet's referential (§7.6). */
export interface RemoteShareRequest {
    id: string;
    node_id: string;
    node_name: string;
    requester_sub: string;
    scope: string[];
    status: 'pending' | 'approved' | 'denied';
    created_at: string;
}

/**
 * List the access requests on the user's personal drive, straight from
 * the enclave. This is the requests screen's source of truth: a push
 * whose sealed payload never arrived (older wallet, key registered
 * after send) still shows up here — just without attributes until the
 * referential knows the sub.
 */
export async function listShareRequests(): Promise<{ tenantId: string; requests: RemoteShareRequest[] }> {
    const s = await ensureDrive();
    if (!s) throw new Error('Drive is unavailable');
    const token = await getPlatformToken();
    const raFetch = makeRaTlsFetch({ enclaveHost: s.origin, platformFetch: fetch });
    const res = await raFetch(
        `https://${s.origin}/v1/tenants/${encodeURIComponent(s.tenant.id)}/link-requests`,
        { headers: { Authorization: `Bearer ${token}` } }
    );
    if (!res.ok) {
        throw new Error(`list requests failed (${res.status})`);
    }
    const j = (await res.json()) as { requests?: RemoteShareRequest[] };
    return { tenantId: s.tenant.id, requests: j.requests ?? [] };
}

/**
 * Approve or deny a restricted-link access request on the user's drive.
 * Runs over the attested RA-TLS transport with the platform bearer (the
 * owner's sub is what authorises the decision on the enclave).
 */
export async function decideShareRequest(
    tenantId: string,
    requestId: string,
    decision: 'approve' | 'deny'
): Promise<void> {
    const s = await ensureDrive();
    if (!s) throw new Error('Drive is unavailable');
    const token = await getPlatformToken();
    const raFetch = makeRaTlsFetch({ enclaveHost: s.origin, platformFetch: fetch });
    const res = await raFetch(
        `https://${s.origin}/v1/tenants/${encodeURIComponent(tenantId)}/link-requests/${encodeURIComponent(requestId)}/${decision}`,
        {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}` }
        }
    );
    if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(`decision failed (${res.status})${body ? `: ${body.slice(0, 200)}` : ''}`);
    }
}

/** Drop the cached drive session (e.g. on sign-out). */
export function clearDrive(): void {
    session = null;
}

export type { DriveNode, Tenant };
