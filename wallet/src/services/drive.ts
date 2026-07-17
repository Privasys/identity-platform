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
 * Gated behind useSettingsStore.driveEnabled while the tab is in progress.
 */

import { PrivasysDrive, type DriveNode, type Tenant } from '@privasys/drive-sdk';

import { getAttestationServerToken } from '@/services/app-attest';
import { inspectAttestation, attestEnclave } from '@/services/attestation';
import { appIdFromOids, OID_WORKLOAD_IMAGE_DIGEST } from '@/services/release-provenance';
import { getPlatformToken } from '@/services/platform-token';
import { useSettingsStore } from '@/stores/settings';
import { makeRaTlsFetch } from '../../modules/native-ratls/src/index';

const PLATFORM_API_BASE =
    process.env.EXPO_PUBLIC_PLATFORM_API_URL ?? 'https://api-test.developer.privasys.org';

/** Store name of the Drive app to resolve. Dev is `drive-demo`; override
 *  per build for a differently-named prod instance. */
const DRIVE_APP_NAME = process.env.EXPO_PUBLIC_DRIVE_APP ?? 'drive-demo';

/** Fallback Drive coordinates, mirroring the identity-verifier pattern
 *  (kyc.ts resolveVerifier): used until the app resolves from the store,
 *  and whenever the resolve API is unreachable — the resolved hostname +
 *  attested digest win when available. Keep the digest pinned to the
 *  live test deployment's image (OID 3.2) so the fallback attests the
 *  current enclave. drive v0.1.22: chat conversations + Memory + graph.
 *  All overridable per build. */
const FALLBACK_DRIVE_ORIGIN =
    process.env.EXPO_PUBLIC_DRIVE_ORIGIN ?? 'drive-demo.apps-test.privasys.org';
const FALLBACK_DRIVE_IMAGE_DIGEST =
    process.env.EXPO_PUBLIC_DRIVE_DIGEST ??
    'fcb068763a21e4e41934bd6554353026b3a96b51ba1cc9ab031f74f99b73e558';
/** The drive-demo app id (management UUID). The data-key grant is keyed
 *  by it. The standing app cert does NOT carry the app-id OID (3.6 lives
 *  on manager-minted identity leaves), so the id comes from the resolve
 *  API; this is the fallback for the offline path. */
const FALLBACK_DRIVE_APP_ID =
    process.env.EXPO_PUBLIC_DRIVE_APP_ID ?? '914b1e13-4e8f-4417-9d8c-eddf580f515b';

interface ResolvedDrive {
    origin: string;
    imageOid: string;
    imageDigest: string;
    appId: string;
}

let resolved: ResolvedDrive | null = null;

/** Parse the app id (management UUID) out of a resolve response. The
 *  endpoint returns it inside `attest_url` (/api/v1/apps/<uuid>/attest)
 *  when a dedicated field is absent. Returns '' when not derivable. */
function appIdFromResolve(j: { app_id?: string; attest_url?: string }): string {
    if (j.app_id) return j.app_id;
    const m = /\/apps\/([0-9a-fA-F-]{36})\//.exec(j.attest_url ?? '');
    return m ? m[1] : '';
}

/** Compare app ids that may differ in form: OID 3.6 carries the
 *  hex-no-dashes UUID, the resolve API the dashed one. */
function sameAppId(a: string, b: string): boolean {
    const norm = (s: string) => s.replace(/-/g, '').toLowerCase();
    return norm(a) === norm(b);
}

/** Resolve the Drive enclave host, the published image digest to pin,
 *  and the management app id, falling back to the build defaults when
 *  the app is not yet in the store or the platform is unreachable
 *  (hardcoded + fallback, same as the identity verifier). Never returns
 *  null: the fallback pins the known-good deployment and attestation
 *  still gates the connection. */
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
                app_id?: string;
                attest_url?: string;
            };
            const appId = appIdFromResolve(j);
            if (j.hostname && j.image_digest && appId) {
                resolved = {
                    origin: j.hostname,
                    imageOid: j.image_oid || OID_WORKLOAD_IMAGE_DIGEST,
                    imageDigest: j.image_digest.toLowerCase(),
                    appId
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
        imageDigest: FALLBACK_DRIVE_IMAGE_DIGEST.toLowerCase(),
        appId: FALLBACK_DRIVE_APP_ID
    };
    return resolved;
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

    // Inspect the RA-TLS cert: pin the published image DIGEST (OID 3.2) —
    // this is the attested proof of WHICH CODE is running and is the real
    // security binding. The app id (used only to key the data-key grant)
    // comes from the resolve API: the standing app cert does not carry the
    // app-id OID (3.6 lives on manager-minted identity leaves). If a leaf
    // ever does present 3.6, cross-check it, but never require it.
    const inspected = await inspectAttestation(d.origin);
    if (d.imageDigest) {
        const got = inspected.custom_oids
            ?.find((o) => o.oid === d.imageOid)
            ?.value_hex?.toLowerCase();
        if (got !== d.imageDigest) {
            throw new Error('Drive enclave image digest does not match the published build');
        }
    }
    const certAppId = appIdFromOids(inspected.custom_oids);
    if (certAppId && d.appId && !sameAppId(certAppId, d.appId)) {
        throw new Error('Drive enclave app id does not match the resolved app');
    }
    const appId = d.appId;
    if (!appId) throw new Error('Drive app id could not be resolved');

    // Full verification through the attestation service, in the user's default
    // mode (deterministic unless they opted into challenge), before any of the
    // user's confidential data flows over the transport. The RA-TLS data plane
    // additionally re-checks the deterministic report_data binding on every
    // request, so a swapped certificate never goes unnoticed.
    const asToken = await getAttestationServerToken();
    const mode = useSettingsStore.getState().verificationMode;
    const outcome = await attestEnclave(d.origin, {
        tee: inspected.tee_type ?? 'tdx',
        mode,
        attestationServerToken: asToken
    });
    if (outcome.status !== 'verified') {
        throw new Error(
            `Drive enclave attestation ${outcome.status}${outcome.message ? `: ${outcome.message}` : ''}`
        );
    }

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
