// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

jest.mock('@/utils/storage', () => {
    const store: Record<string, string> = {};
    return {
        getItemAsync: jest.fn(async (key: string) => store[key] ?? null),
        setItemAsync: jest.fn(async (key: string, value: string) => {
            store[key] = value;
        }),
        deleteItemAsync: jest.fn(async (key: string) => {
            delete store[key];
        }),
    };
});

// Control the transparency-log gate.
jest.mock('@/services/release-provenance', () => ({
    OID_WORKLOAD_APP_ID: '1.3.6.1.4.1.65230.3.6',
    fetchRunningAppReleases: jest.fn(),
}));

import { fetchRunningAppReleases } from '@/services/release-provenance';
import { OID_ATTESTED_DEPENDENCY_SET } from '@/services/dependencies';
import {
    dependenciesNeedPrompt,
    recordDeclaredDependencies,
    resolveDependencyConsent,
} from '@/services/dependency-consent';
import { useDependencyApprovalsStore } from '@/stores/dependency-approvals';

// Build the canonical dependency-set encoding programmatically.
function hex(bytes: number[]): string {
    return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}
function u32(n: number): number[] {
    return [(n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
}
function str(s: string): number[] {
    const b = Array.from(new TextEncoder().encode(s));
    return [...u32(b.length), ...b];
}
function oneEntrySet(appId: string, measurement: string, folded: string): string {
    return hex([
        ...u32(1),
        ...str(appId),
        ...u32(1),
        ...str(measurement),
        ...u32(0), // no required oids
        ...str(folded),
    ]);
}

const customOids = (setHex: string) => [{ oid: OID_ATTESTED_DEPENDENCY_SET, value_hex: setHex }];

beforeEach(() => {
    useDependencyApprovalsStore.setState({ approvals: {} });
    (fetchRunningAppReleases as jest.Mock).mockReset();
});

describe('dependency consent', () => {
    it('classifies a new, published dependency as needing a prompt then approves it', async () => {
        (fetchRunningAppReleases as jest.Mock).mockResolvedValue({
            workload_release: { url: 'https://github.com/x/releases/v1', label: 'v1', matches: true },
        });
        const oids = customOids(oneEntrySet('ai', 'sgx:11', 'ff'));

        const items = await resolveDependencyConsent(oids, 'drive.privasys.org');
        expect(items).toHaveLength(1);
        expect(items[0].status).toBe('new');
        expect(items[0].provenance.published).toBe(true);
        expect(dependenciesNeedPrompt(items)).toBe(true);

        recordDeclaredDependencies(oids, 'approved', 'drive.privasys.org');
        const after = await resolveDependencyConsent(oids, 'drive.privasys.org');
        expect(after[0].status).toBe('approved');
        expect(dependenciesNeedPrompt(after)).toBe(false);
    });

    it('flags an UNPUBLISHED dependency as needing a prompt even if cached approved', async () => {
        (fetchRunningAppReleases as jest.Mock).mockResolvedValue(null); // not a published build
        const oids = customOids(oneEntrySet('rogue', 'sgx:22', ''));
        recordDeclaredDependencies(oids, 'approved', 'drive.privasys.org');

        const items = await resolveDependencyConsent(oids, 'drive.privasys.org');
        expect(items[0].provenance.published).toBe(false);
        // The transparency-log gate forces a prompt despite the cached approval.
        expect(dependenciesNeedPrompt(items)).toBe(true);
    });

    it('returns [] when the enclave declares no dependencies', async () => {
        expect(await resolveDependencyConsent([], undefined)).toEqual([]);
        expect(await resolveDependencyConsent(undefined, undefined)).toEqual([]);
    });
});
