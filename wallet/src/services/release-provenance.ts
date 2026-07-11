// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Release provenance — link an app measurement/version to its published GitHub
 * release and the code changes since the last promoted version.
 *
 * The management service resolves this from the app catalogue + the
 * version_promotions ledger, computes the digest `matches` verdict server-side
 * (attacker-unforgeable given trust in mgmt), and exposes two public endpoints:
 *
 *   GET /api/v1/apps/{id}/versions/{vid}/release-provenance[?digest=<oid3.2 hex>]
 *       Works for ANY version, no running enclave needed — used on the vault
 *       APPROVAL screen for the promote TARGET (a not-yet-running measurement).
 *   GET /api/v1/apps/{id}/attest
 *       Live attestation of the currently-deployed enclave; carries os_release +
 *       workload_release (with matches) — used on Service Details for a RUNNING
 *       app the wallet is connected to.
 *
 * Framing: this is "verified by Privasys" (the OID 3.2 digest → GitHub release
 * mapping is mgmt's assertion), not a trustless reproducible-build proof. The
 * hardware-rooted anchor remains the attested quote / the vault binding.
 */

const PROD_API_BASE = 'https://api.developer.privasys.org';
const DEV_API_BASE = 'https://api-test.developer.privasys.org';
const DEFAULT_API_BASE = process.env.EXPO_PUBLIC_PLATFORM_API_URL ?? DEV_API_BASE;

/**
 * Ordered control-plane candidates for an app. The wallet build pins ONE
 * platform API via EXPO_PUBLIC_PLATFORM_API_URL, but a production wallet is
 * routinely shown dev apps (…apps-test.privasys.org) and vice versa — and an
 * app id only exists on its own control plane, so asking the wrong one 404s
 * and the release card silently vanished. Prefer the base implied by the app
 * host, then fall back through the known environments; a wrong base costs one
 * fast 404, nothing else.
 */
function apiBasesForHost(appHost?: string): string[] {
    const preferred = appHost?.endsWith('.apps-test.privasys.org')
        ? DEV_API_BASE
        : appHost?.endsWith('.apps.privasys.org')
            ? PROD_API_BASE
            : DEFAULT_API_BASE;
    return [...new Set([preferred, DEFAULT_API_BASE, PROD_API_BASE, DEV_API_BASE])];
}

/** The published container package/release the code was built from. */
export interface WorkloadRelease {
    /** GitHub release page (preferred) or GHCR package page. */
    url?: string;
    /** Version semver, e.g. "v0.1.3". */
    label?: string;
    /** Published image digest (bare hex sha256). */
    digest?: string;
    /** OID 3.2 (attested/target) == the published digest. Absent when unknown. */
    matches?: boolean;
}

/** The enclave-OS GitHub release the measurements were verified against. */
export interface OsRelease {
    url?: string;
    tag?: string;
    status?: string; // 'verified' | 'mismatch' | 'unverified' | ''
}

/** The previously-promoted version + a GitHub compare (old→new) link. */
export interface PreviousRelease {
    label?: string;
    compare_url?: string;
}

/** Release provenance for one app version (the promote-target endpoint). */
export interface ReleaseProvenance {
    version?: { label?: string; version_number?: number };
    workload_release?: WorkloadRelease;
    previous?: PreviousRelease;
    /** Present only when a ?digest= was supplied. */
    matches?: boolean;
}

/** OID 3.2 (workload image digest) and 3.6 (workload app id) on the RA-TLS leaf. */
export const OID_WORKLOAD_IMAGE_DIGEST = '1.3.6.1.4.1.65230.3.2';
export const OID_WORKLOAD_APP_ID = '1.3.6.1.4.1.65230.3.6';

/**
 * Re-dash the OID 3.6 app-id (32-char undashed hex) into the management-service
 * UUID form the release endpoints expect. Returns undefined when absent/malformed.
 */
export function appIdFromOids(
    customOids?: Array<{ oid: string; value_hex: string }>
): string | undefined {
    const hex = customOids?.find((o) => o.oid === OID_WORKLOAD_APP_ID)?.value_hex?.toLowerCase();
    if (!hex || !/^[0-9a-f]{32}$/.test(hex)) return undefined;
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

async function getJSON<T>(url: string): Promise<T | null> {
    try {
        const res = await fetch(url, { headers: { Accept: 'application/json' } });
        if (!res.ok) return null;
        return (await res.json()) as T;
    } catch {
        return null;
    }
}

/** GET `path` from the first control-plane candidate that answers. */
async function getJSONFirst<T>(path: string, appHost?: string): Promise<T | null> {
    for (const base of apiBasesForHost(appHost)) {
        const result = await getJSON<T>(`${base}${path}`);
        if (result) return result;
    }
    return null;
}

/**
 * Resolve the published release + code-diff for a specific app version. Public;
 * no enclave needs to be running. Pass `digest` (the target OID 3.2 hex) to also
 * get the `matches` verdict. Returns null on any failure — the caller degrades
 * to no release card.
 */
export async function fetchReleaseProvenance(
    appId: string,
    versionId: string,
    digest?: string,
    appHost?: string
): Promise<ReleaseProvenance | null> {
    if (!appId || !versionId) return null;
    const q = digest ? `?digest=${encodeURIComponent(digest)}` : '';
    return getJSONFirst<ReleaseProvenance>(
        `/api/v1/apps/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}/release-provenance${q}`,
        appHost
    );
}

/**
 * The release links stamped on a RUNNING app's live attestation (os_release +
 * workload_release). Used on Service Details for a connected enclave app whose
 * management app id we know (OID 3.6). Returns null on failure.
 */
export async function fetchRunningAppReleases(
    appId: string,
    appHost?: string
): Promise<{ os_release?: OsRelease; workload_release?: WorkloadRelease } | null> {
    if (!appId) return null;
    const data = await getJSONFirst<{ os_release?: OsRelease; workload_release?: WorkloadRelease }>(
        `/api/v1/apps/${encodeURIComponent(appId)}/attest`,
        appHost
    );
    if (!data) return null;
    return { os_release: data.os_release, workload_release: data.workload_release };
}
