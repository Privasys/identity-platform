// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Ties the attested-dependency pieces together for the connect flow: decode an
 * enclave's declared dependencies (OID 6.1), classify each against the approval
 * cache, resolve a human name + published-build provenance (the transparency-log
 * gate), and record the user's decisions with provenance.
 *
 * This is the data layer the UI drives — see connect.tsx.
 */

import {
    DeclaredDependency,
    dependenciesFromCustomOids,
    dependencyIdentity,
} from '@/services/dependencies';
import { fetchRunningAppReleases, WorkloadRelease } from '@/services/release-provenance';
import { DependencyStatus, useDependencyApprovalsStore } from '@/stores/dependency-approvals';

export interface DependencyProvenance {
    /** Human app name (release label / app-id fallback). */
    name: string;
    /** GitHub release / package page for the pinned build, if any. */
    url?: string;
    /** Version label, e.g. "v0.1.3". */
    label?: string;
    /**
     * The transparency-log gate: true only when the dependency's app-id resolves
     * to a PUBLISHED build (a release the platform will attest). A dependency that
     * does not resolve to a published build must not be silently approved — it is
     * the sticky-approval + rollback guard from the design.
     */
    published: boolean;
}

export interface DependencyConsentItem {
    dependency: DeclaredDependency;
    /** The (app-id, identity) cache key's identity half. */
    identity: string;
    status: DependencyStatus;
    previouslyDenied: boolean;
    provenance: DependencyProvenance;
}

function provenanceFromRelease(appId: string, wr?: WorkloadRelease): DependencyProvenance {
    const published = !!(wr && (wr.url || wr.matches));
    return {
        name: wr?.label ? `${appId.slice(0, 8)} ${wr.label}` : appId,
        url: wr?.url,
        label: wr?.label,
        published,
    };
}

/**
 * Classify a connecting enclave's declared dependencies: decode them, look each
 * up in the approval cache (approved → silent, denied → remind, new → prompt),
 * and resolve provenance + the published-build gate for each. Returns [] when the
 * enclave declares none.
 */
export async function resolveDependencyConsent(
    customOids: Array<{ oid: string; value_hex: string }> | undefined,
    appHost?: string
): Promise<DependencyConsentItem[]> {
    const declared = dependenciesFromCustomOids(customOids);
    if (declared.length === 0) return [];

    const store = useDependencyApprovalsStore.getState();
    const decisions = store.evaluate(declared);

    return Promise.all(
        decisions.map(async (d) => {
            let wr: WorkloadRelease | undefined;
            try {
                const releases = await fetchRunningAppReleases(d.dependency.appId, appHost);
                wr = releases?.workload_release;
            } catch {
                wr = undefined;
            }
            return {
                dependency: d.dependency,
                identity: d.identity,
                status: d.status,
                previouslyDenied: d.previouslyDenied,
                provenance: provenanceFromRelease(d.dependency.appId, wr),
            };
        })
    );
}

/**
 * Record the user's decision on a connecting enclave's declared dependencies,
 * keyed by (app-id, identity), with the parent app as provenance. Approving a
 * dependency here is reused for every other app that pulls in the same identity.
 */
export function recordDependencyDecisions(
    items: DependencyConsentItem[],
    decision: 'approved' | 'denied',
    parentRpId: string
): void {
    const store = useDependencyApprovalsStore.getState();
    for (const item of items) {
        store.record({
            appId: item.dependency.appId,
            identity: item.identity,
            decision,
            parentRpId,
            appName: item.provenance.name,
        });
    }
}

/**
 * Record a decision on an enclave's declared dependencies straight from its
 * certificate OIDs, without the async provenance fetch — used at the moment of
 * approval where latency matters. Keyed by (app-id, identity), provenance = the
 * parent app. No-op when the enclave declares no dependencies.
 */
export function recordDeclaredDependencies(
    customOids: Array<{ oid: string; value_hex: string }> | undefined,
    decision: 'approved' | 'denied',
    parentRpId: string
): void {
    const declared = dependenciesFromCustomOids(customOids);
    if (declared.length === 0) return;
    const store = useDependencyApprovalsStore.getState();
    for (const dep of declared) {
        store.record({
            appId: dep.appId,
            identity: dependencyIdentity(dep),
            decision,
            parentRpId,
            appName: dep.appId,
        });
    }
}

/**
 * Whether a set of dependency-consent items can be auto-approved silently: every
 * one is already approved in the cache AND resolves to a published build. Any new,
 * previously-denied, or unpublished dependency needs the user to decide.
 */
export function dependenciesNeedPrompt(items: DependencyConsentItem[]): boolean {
    return items.some((i) => i.status !== 'approved' || !i.provenance.published);
}

export { dependencyIdentity };
