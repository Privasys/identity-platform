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

/** Store name of the Drive app to resolve. */
const DRIVE_APP_NAME = process.env.EXPO_PUBLIC_DRIVE_APP ?? 'container-app-drive';

interface ResolvedDrive {
    origin: string;
    imageOid: string;
    imageDigest: string; // '' when the resolve channel gave none (no pin)
}

let resolved: ResolvedDrive | null = null;

/** Resolve the Drive enclave host + the published image digest to pin. Returns
 *  null when the app is not resolvable (feature simply stays unavailable). */
async function resolveDrive(): Promise<ResolvedDrive | null> {
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
            if (j.hostname) {
                resolved = {
                    origin: j.hostname,
                    imageOid: j.image_oid || OID_WORKLOAD_IMAGE_DIGEST,
                    imageDigest: (j.image_digest ?? '').toLowerCase()
                };
                return resolved;
            }
        }
    } catch {
        // fall through
    }
    return null;
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
    if (!d) return null;

    // Inspect the RA-TLS cert: pin the published image digest and read the
    // management app id (OID 3.6) the data-key grant is keyed by.
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
