// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Public App Store listing for one app, used by the approval screen to say who
 * is asking rather than making a name out of DNS.
 *
 * The endpoint is unauthenticated and keyed by SLUG, and the slug is already in
 * hand: `app.Name` in the management service IS the store slug, and the first
 * label of an app hostname is that same name (`drive.apps.privasys.org` ->
 * `drive`). So the approval screen needs no new plumbing to identify an app.
 *
 * Every field is best-effort. A missing listing is a REAL ANSWER, not an error
 * to paper over: it means the publisher never filled one in, and the approval
 * screen says so rather than inventing a display name. See the callers.
 */

import { publicApiGet, type WorkloadRelease } from '@/services/release-provenance';

/** Reproducible-build provenance the store publishes for an app. */
export interface StoreReproducibility {
    source_type?: string;
    container_image?: string;
    cwasm_hash?: string;
    cwasm_url?: string;
    /** Source commit / repository page on GitHub. */
    commit_url?: string;
    /** The reproducible-build GitHub Actions run. */
    build_run_url?: string;
    enclave_os_release_url?: string;
}

export interface StoreListing {
    slug: string;
    name: string;
    /** Publisher, as the store has it. May be a person, may be empty. */
    developer: string;
    category: string;
    tagline: string;
    description: string;
    icon_url: string;
    website_url?: string;
    privacy_url?: string;
    tos_url?: string;
    support_email?: string;
    reproducibility?: StoreReproducibility;
}

/**
 * The store slug for an app host: the first DNS label of a host that HAS a
 * subdomain.
 *
 * Three labels minimum, which is not fussiness. A bare `privasys.id` would
 * otherwise yield the slug `privasys`, and `privasys.id` is exactly the FIDO2
 * rpId every IdP-brokered ceremony shares. Looking that up would name the
 * identity provider on a screen whose entire job is to name the app.
 *
 * The label is also validated rather than merely encoded: it comes from a host
 * in a QR code an attacker chooses, and it is interpolated into a request path.
 */
export function slugForHost(host: string): string | undefined {
    const labels = host.trim().toLowerCase().split('.');
    if (labels.length < 3) return undefined;
    const label = labels[0];
    return /^[a-z0-9][a-z0-9-]*$/.test(label) ? label : undefined;
}

/**
 * Fetch the public listing for a host. Returns null when the app has no
 * published listing, when the host has no slug, or on any network failure —
 * all three are the same thing to the caller, which is "we cannot name this
 * app" and must say so.
 */
export async function fetchStoreListing(host: string): Promise<StoreListing | null> {
    const slug = slugForHost(host);
    if (!slug) return null;
    const listing = await publicApiGet<StoreListing>(
        `/api/v1/store/apps/${encodeURIComponent(slug)}`,
        host,
    );
    // A listing with no name is indistinguishable from no listing for our
    // purposes, and treating it as one keeps the fallback path single.
    return listing?.name ? listing : null;
}

/**
 * Repository link for an app: the store's commit URL, and nothing else.
 *
 * It deliberately does NOT fall back to the attested release URL. That URL is
 * "a GitHub release page or a GHCR package page" (see WorkloadRelease), and an
 * app built from a published image has only the latter. Labelling a container
 * package page "Source code" on a screen whose whole job is to let someone
 * check what is running would be a claim we cannot support: a package page
 * shows a digest, not the code that produced it.
 *
 * Verified against the live store on 2026-08-26: Privasys Drive is
 * `source_type: package` with no commit_url, so this correctly returns
 * undefined and the row is dropped. The release link still appears, labelled
 * as a version, in All other details.
 */
export function sourceUrl(listing: StoreListing | null | undefined): string | undefined {
    return listing?.reproducibility?.commit_url || undefined;
}

/**
 * Short label for a repository URL: `Privasys/drive` from any github.com URL,
 * else the host. Full URLs do not fit a properties row, and a truncated URL is
 * worse than a short name because it hides the tail.
 */
export function sourceLabel(url: string): string {
    try {
        const u = new URL(url);
        if (u.hostname.endsWith('github.com')) {
            const parts = u.pathname.split('/').filter(Boolean);
            if (parts.length >= 2) return `${parts[0]}/${parts[1]}`;
        }
        return u.hostname;
    } catch {
        return url;
    }
}

/**
 * The Source code row: the store's commit URL when the app is published, else
 * the commit the running version's own provenance records.
 *
 * The second half matters because an unpublished app has no listing at all, so
 * the row used to vanish for exactly the apps whose code a holder most needs to
 * look at. The version's commit is the same fact from the other endpoint.
 *
 * The label carries the short SHA when we have one: a repository name alone
 * points at whatever the default branch holds today, not at what was built.
 */
export function sourceRow(
    listing: StoreListing | null | undefined,
    workload: WorkloadRelease | null | undefined,
): { url: string; label: string } | undefined {
    const fromListing = sourceUrl(listing);
    const url = fromListing ?? workload?.commit_url;
    if (!url) return undefined;
    const sha = !fromListing && workload?.commit ? workload.commit.slice(0, 7) : '';
    return { url, label: sha ? `${sourceLabel(url)}@${sha}` : sourceLabel(url) };
}
