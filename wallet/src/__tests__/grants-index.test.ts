// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The grants index, and the caller-side revoke.
 *
 * The index exists so a recovered phone can find the holder's standing grants
 * again, an unattended holder folder among them, and put the revoke button back
 * under each. What it must never do is resurrect a grant the holder ended, take
 * a row on trust from the backup, or let an unreachable service cost them the
 * rest.
 */

jest.mock('../../modules/native-ratls/src/index', () => ({ makeRaTlsFetch: jest.fn() }));
jest.mock('@/services/platform-token', () => ({ getPlatformToken: jest.fn(async () => 'tok') }));
jest.mock('@/services/wallet-call', () => ({
    walletCallHeaders: jest.fn(async () => ({ 'X-Privasys-Wallet-Proof': 'proof' })),
}));
jest.mock('expo-crypto', () => ({
    getRandomBytes: (n: number) => new Uint8Array(n).map((_, i) => (i * 7 + 3) & 0xff),
}));
jest.mock('@/utils/storage', () => {
    const mockStore: Record<string, string> = {};
    return {
        getItemAsync: jest.fn(async (k: string) => mockStore[k] ?? null),
        setItemAsync: jest.fn(async (k: string, v: string) => {
            mockStore[k] = v;
        }),
        deleteItemAsync: jest.fn(async (k: string) => {
            delete mockStore[k];
        }),
    };
});
const mockRoot = new Uint8Array(32).map((_, i) => i + 1);
jest.mock('@/services/sovereign', () => ({ ensureDataRoot: jest.fn(async () => mockRoot) }));
jest.mock('@/services/app-resolve', () => ({ resolveApp: jest.fn() }));

import { makeRaTlsFetch } from '../../modules/native-ratls/src/index';
import { resolveApp } from '@/services/app-resolve';
import { revokeAtCallingApp } from '@/services/capabilities';
import {
    __resetGrantsIndexForTests,
    buildIndex,
    dashedAppId,
    openIndex,
    rebuildFromGrantsIndex,
    recordFromHeld,
    sealIndex,
    syncGrantsIndex,
} from '@/services/grants-index';
import { useCapabilitiesStore, type CapabilityRecord } from '@/stores/capabilities';

const raTls = makeRaTlsFetch as unknown as jest.Mock;
const resolve = resolveApp as unknown as jest.Mock;

const APP = '3f6d1a0e-0000-4000-8000-000000000001';
const DRIVE = '11111111-2222-4333-8444-555555555555';
const FOLDER_URL = 'https://privasystant.apps.test.privasys.org/__privasys/v1/capabilities';

const rec = (over: Partial<CapabilityRecord> = {}): CapabilityRecord => ({
    appId: APP,
    appName: 'Privasystant',
    resourceAppId: DRIVE,
    kind: 'storage.folder',
    resourceLabel: 'Harness',
    permissions: ['read', 'write'],
    decision: 'approved',
    capabilityId: 'cap-1',
    grantedAt: 1_800_000_000,
    ...over,
});

beforeEach(() => {
    __resetGrantsIndexForTests();
    useCapabilitiesStore.setState({ records: [], hydrated: true });
    raTls.mockReset();
    resolve.mockReset();
    (global as any).fetch = jest.fn();
});

describe('buildIndex', () => {
    // The index holds where to ask, not the grants: two grants at one service
    // are one entry.
    it('lists each service once', () => {
        const i = buildIndex([rec(), rec({ capabilityId: 'cap-2', resourceLabel: 'Other' })]);
        expect(i.services).toEqual([{ resourceAppId: DRIVE }]);
    });

    it('keeps the exact service_url for a holder folder', () => {
        const i = buildIndex([rec({ kind: 'app_storage', resourceAppId: APP, serviceUrl: FOLDER_URL })]);
        expect(i.services).toEqual([{ resourceAppId: APP, serviceUrl: FOLDER_URL }]);
    });

    // Nothing to rebuild for these, and nothing a service would list.
    it('leaves out revoked grants, denials and grants with no id', () => {
        const i = buildIndex([
            rec({ revokedAt: 1 }),
            rec({ decision: 'denied', capabilityId: 'cap-x' }),
            rec({ capabilityId: undefined }),
        ]);
        expect(i.services).toEqual([]);
    });

    // What the service's list cannot say: which grants carry a credential, and
    // the service's own labels for it. Labels, never values.
    it('keeps the extras the list cannot give back', () => {
        const i = buildIndex([rec({ setupProvided: true, secretLabels: ['App password'] })]);
        expect(i.extras).toEqual({ 'cap-1': { setupProvided: true, secretLabels: ['App password'] } });
    });

    // Order-independent, so re-reading the same grants in another order is
    // not mistaken for a change worth uploading.
    it('is the same whatever order the grants are in', () => {
        const a = rec();
        const b = rec({ resourceAppId: APP, serviceUrl: FOLDER_URL, capabilityId: 'hf_1' });
        expect(JSON.stringify(buildIndex([a, b]))).toBe(JSON.stringify(buildIndex([b, a])));
    });
});

describe('sealing', () => {
    const index = buildIndex([rec()]);

    it('opens with the same root', () => {
        expect(openIndex(mockRoot, sealIndex(mockRoot, index))).toEqual(index);
    });

    // Another identity's root, as after a wipe and a fresh profile: nothing.
    it('does not open with another root', () => {
        expect(openIndex(new Uint8Array(32).fill(9), sealIndex(mockRoot, index))).toBeNull();
    });

    it('does not open when tampered with', () => {
        const blob = sealIndex(mockRoot, index);
        const flipped = blob.slice(0, -4) + (blob.endsWith('A') ? 'B' : 'A') + blob.slice(-3);
        expect(openIndex(mockRoot, flipped)).toBeNull();
    });

    it('does not open a blob it does not recognise', () => {
        expect(openIndex(mockRoot, 'AAAA')).toBeNull();
        expect(openIndex(mockRoot, 'not base64 at all!!')).toBeNull();
    });
});

describe('recordFromHeld', () => {
    it('rebuilds a row from what the service says', () => {
        const r = recordFromHeld(
            {
                capability_id: 'hf_1',
                kind: 'app_storage',
                permissions: ['read', 'write'],
                resource_label: 'Your working files',
                subject_app_id: 'app:3f6d1a0e000040008000000000000001',
                created_unix: 1_800_000_100,
                expires_unix: 0,
                unattended: true,
            },
            { resourceAppId: APP, serviceUrl: FOLDER_URL },
            undefined,
            { appName: 'Privasystant' },
            1_800_000_500,
        )!;
        expect(r.appId).toBe(APP);
        expect(r.capabilityId).toBe('hf_1');
        expect(r.serviceUrl).toBe(FOLDER_URL);
        expect(r.unattended).toBe(true);
        expect(r.expiresAt).toBeUndefined();
        expect(r.grantedAt).toBe(1_800_000_100);
        // The service's answer, so confirmed rather than this device's record.
        expect(r.checkResult).toBe('held');
    });

    // Same rule as the approval screen: a kind or a permission the wallet
    // cannot describe is not one it will put under a button.
    it.each([
        [{ kind: 'vault.sign', permissions: ['read'] }],
        [{ kind: 'storage.folder', permissions: ['read', 'administer'] }],
        [{ kind: 'storage.folder', permissions: [] }],
    ])('refuses %p', (bad) => {
        expect(
            recordFromHeld({ capability_id: 'x', ...bad } as never, { resourceAppId: DRIVE }, undefined, {}, 1),
        ).toBeNull();
    });

    it.each([
        ['app:3f6d1a0e000040008000000000000001', APP],
        ['3f6d1a0e000040008000000000000001', APP],
        [APP, APP],
    ])('reads the subject %p as %p', (raw, want) => {
        expect(dashedAppId(raw)).toBe(want);
    });
});

describe('rebuildFromGrantsIndex', () => {
    function idpServes(blob: string | null) {
        (global as any).fetch = jest.fn(async () =>
            blob
                ? { ok: true, status: 200, json: async () => ({ blob }) }
                : { ok: false, status: 404, json: async () => ({}) },
        );
    }

    function servicesList(byHost: Record<string, unknown[] | 'down'>) {
        raTls.mockImplementation(({ enclaveHost }: { enclaveHost: string }) => async () => {
            const answer = byHost[enclaveHost];
            if (answer === 'down') throw new Error('unreachable');
            return { ok: true, status: 200, json: async () => ({ capabilities: answer ?? [] }) };
        });
    }

    // The case this exists for: a recovered phone with no rows.
    it('puts back a holder folder this phone has no row for', async () => {
        idpServes(sealIndex(mockRoot, buildIndex([rec({
            kind: 'app_storage', resourceAppId: APP, serviceUrl: FOLDER_URL, capabilityId: 'hf_1', unattended: true,
        })])));
        servicesList({
            'privasystant.apps.test.privasys.org': [{
                capability_id: 'hf_1', kind: 'app_storage', permissions: ['read', 'write'],
                resource_label: 'Your working files', subject_app_id: APP, unattended: true,
            }],
        });
        resolve.mockResolvedValue({ display_name: 'Privasystant', hostname: 'privasystant.apps.test.privasys.org' });

        expect(await rebuildFromGrantsIndex()).toBe(1);
        const [row] = useCapabilitiesStore.getState().records;
        expect(row.capabilityId).toBe('hf_1');
        expect(row.serviceUrl).toBe(FOLDER_URL);
        expect(row.appName).toBe('Privasystant');
    });

    // Never resurrect what the holder ended: the service does not list it, so
    // the index naming the service is not enough to bring it back.
    it('does not bring back a grant the service no longer holds', async () => {
        idpServes(sealIndex(mockRoot, buildIndex([rec()])));
        servicesList({ 'drive.example.org': [] });
        resolve.mockResolvedValue({ hostname: 'drive.example.org', display_name: 'Drive' });
        expect(await rebuildFromGrantsIndex()).toBe(0);
        expect(useCapabilitiesStore.getState().records).toEqual([]);
    });

    // A second phone, or a second launch: rows it already has are left alone.
    it('does not duplicate a row this phone already has', async () => {
        useCapabilitiesStore.setState({ records: [rec()], hydrated: true });
        idpServes(sealIndex(mockRoot, buildIndex([rec()])));
        servicesList({
            'drive.example.org': [{ capability_id: 'cap-1', kind: 'storage.folder', permissions: ['read', 'write'] }],
        });
        resolve.mockResolvedValue({ hostname: 'drive.example.org', display_name: 'Drive' });
        expect(await rebuildFromGrantsIndex()).toBe(0);
        expect(useCapabilitiesStore.getState().records).toHaveLength(1);
    });

    // One unreachable service must not cost the holder the others.
    it('carries on past a service that cannot be reached', async () => {
        idpServes(sealIndex(mockRoot, buildIndex([
            rec(),
            rec({ kind: 'app_storage', resourceAppId: APP, serviceUrl: FOLDER_URL, capabilityId: 'hf_1' }),
        ])));
        servicesList({
            'drive.example.org': 'down',
            'privasystant.apps.test.privasys.org': [{
                capability_id: 'hf_1', kind: 'app_storage', permissions: ['read'], subject_app_id: APP,
            }],
        });
        resolve.mockResolvedValue({ hostname: 'drive.example.org', display_name: 'Drive' });
        expect(await rebuildFromGrantsIndex()).toBe(1);
    });

    it('does nothing for a holder with no index', async () => {
        idpServes(null);
        expect(await rebuildFromGrantsIndex()).toBe(0);
    });

    it('runs once per launch', async () => {
        idpServes(null);
        await rebuildFromGrantsIndex();
        await rebuildFromGrantsIndex();
        expect((global as any).fetch).toHaveBeenCalledTimes(1);
    });
});

describe('syncGrantsIndex', () => {
    it('uploads when the grants change, and not when they do not', async () => {
        const put = jest.fn(async () => ({ ok: true, status: 200 }));
        (global as any).fetch = put;
        useCapabilitiesStore.setState({ records: [rec()], hydrated: true });

        await syncGrantsIndex();
        await syncGrantsIndex();
        expect(put).toHaveBeenCalledTimes(1);

        useCapabilitiesStore.setState({ records: [rec(), rec({ capabilityId: 'cap-2', resourceAppId: APP })], hydrated: true });
        await syncGrantsIndex();
        expect(put).toHaveBeenCalledTimes(2);
    });

    // A refused upload is not remembered as done, so it is retried.
    it('retries after a refused upload', async () => {
        const put = jest
            .fn()
            .mockResolvedValueOnce({ ok: false, status: 500 })
            .mockResolvedValue({ ok: true, status: 200 });
        (global as any).fetch = put;
        useCapabilitiesStore.setState({ records: [rec({ capabilityId: 'cap-retry' })], hydrated: true });
        await syncGrantsIndex();
        await syncGrantsIndex();
        expect(put).toHaveBeenCalledTimes(2);
    });

    it('never throws', async () => {
        (global as any).fetch = jest.fn(async () => {
            throw new Error('offline');
        });
        useCapabilitiesStore.setState({ records: [rec({ capabilityId: 'cap-offline' })], hydrated: true });
        await expect(syncGrantsIndex()).resolves.toBeUndefined();
    });
});

describe('revokeAtCallingApp', () => {
    const calls: { url: string; method?: string; headers?: Record<string, string> }[] = [];
    beforeEach(() => {
        calls.length = 0;
        raTls.mockImplementation(() => async (url: string, init?: { method?: string; headers?: Record<string, string> }) => {
            calls.push({ url, method: init?.method, headers: init?.headers });
            return { ok: true, status: 200, text: async () => '' };
        });
    });

    // Tells the app that asked, at the prefix the enclave OS reserves on every
    // app host, with the proof, so the app stops saying "approved".
    it('deletes the record at the calling app host', async () => {
        const out = await revokeAtCallingApp({
            callingAppId: APP,
            capabilityId: 'cap-1',
            resourceHost: 'drive.example.org',
            resolve: async () => ({ hostname: 'harness.apps.example.org' }),
        });
        expect(out).toBe('told');
        expect(calls[0].method).toBe('DELETE');
        expect(calls[0].url).toBe('https://harness.apps.example.org/__privasys/v1/capabilities/cap-1');
        expect(calls[0].headers?.['X-Privasys-Wallet-Proof']).toBe('proof');
    });

    // A holder folder: the app IS the service, so the one DELETE already did
    // both. A second would be a second Face ID prompt for nothing.
    it('does nothing more when the calling app is the service', async () => {
        const out = await revokeAtCallingApp({
            callingAppId: APP,
            capabilityId: 'hf_1',
            resourceHost: 'privasystant.apps.test.privasys.org',
            resolve: async () => ({ hostname: 'privasystant.apps.test.privasys.org' }),
        });
        expect(out).toBe('same-host');
        expect(calls).toHaveLength(0);
    });

    // The holder's access is already gone; the app's view lagging is logged,
    // not put in front of them as a failure.
    it('never throws', async () => {
        raTls.mockImplementation(() => async () => {
            throw new Error('unreachable');
        });
        await expect(
            revokeAtCallingApp({
                callingAppId: APP,
                capabilityId: 'cap-1',
                resourceHost: 'drive.example.org',
                resolve: async () => ({ hostname: 'harness.apps.example.org' }),
            }),
        ).resolves.toBe('skipped');
    });

    // A record from before the runtime kept subjects answers 404: nothing to
    // drop, which is fine.
    it('treats a 404 from the calling app as done', async () => {
        raTls.mockImplementation(() => async () => ({ ok: false, status: 404, text: async () => '' }));
        await expect(
            revokeAtCallingApp({
                callingAppId: APP,
                capabilityId: 'old',
                resourceHost: 'drive.example.org',
                resolve: async () => ({ hostname: 'harness.apps.example.org' }),
            }),
        ).resolves.toBe('told');
    });
});
