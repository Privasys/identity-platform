// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

jest.mock('@/utils/storage', () => {
    const mockStore: Record<string, string> = {};
    return {
        mockStore,
        getItemAsync: jest.fn(async (k: string) => mockStore[k] ?? null),
        setItemAsync: jest.fn(async (k: string, v: string) => {
            mockStore[k] = v;
        }),
        deleteItemAsync: jest.fn(async (k: string) => {
            delete mockStore[k];
        }),
    };
});

import { checkReshare, reshareDigest, vaultReleaseFor, forgetPublishedReleases, forgetVaultReleases } from '@/services/vault-reshare';

// The vault's own vector (enclave-os-vault reshare_context; the Go client and
// an independent script agree).
const VECTOR = 'e6077b2adf28720e9348c478cc1668cf47604c8b4ede5d3def858bc65d7b6ea6';
const fields = {
    handle: 'vaults/x/k',
    measurement: VECTOR,
    target_mrenclave: '09'.repeat(32),
    target_vaults: 'a:1,b:2,c:3',
    threshold: '2',
    helpers: '1,3',
    public_key: Buffer.alloc(32, 1).toString('base64url'),
};

describe('reshare digest', () => {
    it('matches the vault', () => {
        expect(
            reshareDigest({
                handle: 'vaults/x/k',
                groupKey: new Uint8Array(32).fill(1),
                helpers: [1, 3],
                threshold: 2,
                vaults: ['a:1', 'b:2', 'c:3'],
                mrenclave: new Uint8Array(32).fill(9),
            }),
        ).toBe(VECTOR);
    });

    it('accepts fields that recompute to the bound measurement', () => {
        expect(checkReshare(fields)).toEqual({
            mrenclave: '09'.repeat(32),
            vaults: ['a:1', 'b:2', 'c:3'],
            threshold: 2,
            helpers: [1, 3],
        });
    });

    it('refuses a target build, vault list, threshold or key the approval does not bind', () => {
        expect(checkReshare({ ...fields, target_mrenclave: '6b516eab16067c519627e6fe26b636da861ccf5722f20ea37ef6559b8925b435' })).toBeNull();
        expect(checkReshare({ ...fields, target_vaults: 'b:2,a:1,c:3' })).toBeNull();
        expect(checkReshare({ ...fields, threshold: '3' })).toBeNull();
        expect(checkReshare({ ...fields, helpers: '1,2' })).toBeNull();
        expect(checkReshare({ ...fields, public_key: Buffer.alloc(32, 2).toString('base64url') })).toBeNull();
        expect(checkReshare({ ...fields, handle: 'vaults/x/other' })).toBeNull();
    });

    it('refuses missing or malformed fields', () => {
        expect(checkReshare({ ...fields, target_mrenclave: undefined })).toBeNull();
        expect(checkReshare({ ...fields, public_key: 'AQ' })).toBeNull();
        expect(checkReshare({ ...fields, threshold: '0' })).toBeNull();
        expect(checkReshare({ ...fields, threshold: '4' })).toBeNull();
        expect(checkReshare({ ...fields, helpers: '1,x' })).toBeNull();
        expect(checkReshare({ ...fields, target_vaults: 'a:1,,c:3' })).toBeNull();
    });
});

describe('vault release lookup', () => {
    const fetchMock = jest.fn();
    beforeEach(async () => {
        forgetPublishedReleases();
        await forgetVaultReleases();
        fetchMock.mockReset();
        (global as any).fetch = fetchMock;
    });

    it('names a pinned release without asking GitHub', async () => {
        const r = await vaultReleaseFor('6B516EAB16067C519627E6FE26B636DA861CCF5722F20EA37EF6559B8925B435');
        expect(r).toEqual({ version: 'v0.39.0', url: 'https://github.com/Privasys/enclave-vaults/releases/tag/vault-v0.39.0' });
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('reads newer releases from GitHub, skipping prereleases and other tags', async () => {
        const dl = (tag: string) => `https://github.com/Privasys/enclave-vaults/releases/download/${tag}/mrenclave.txt`;
        const asset = (tag: string) => [{ name: 'mrenclave.txt', browser_download_url: dl(tag) }];
        const bodies: Record<string, string> = {
            [dl('vault-v0.40.0')]: 'aa'.repeat(32) + '\n',
            [dl('vault-v0.41.0')]: 'bb'.repeat(32),
            [dl('dev-v0.40.0')]: 'cc'.repeat(32),
        };
        fetchMock.mockImplementation(async (url: string) => {
            if (url.startsWith('https://api.github.com/')) {
                return {
                    ok: true,
                    json: async () => [
                        { tag_name: 'vault-v0.41.0', prerelease: true, assets: asset('vault-v0.41.0') },
                        { tag_name: 'dev-v0.40.0', assets: asset('dev-v0.40.0') },
                        { tag_name: 'vault-v0.40.0', assets: asset('vault-v0.40.0') },
                    ],
                };
            }
            return { ok: true, text: async () => bodies[url] };
        });
        expect((await vaultReleaseFor('aa'.repeat(32)))?.version).toBe('v0.40.0');
        expect(await vaultReleaseFor('bb'.repeat(32))).toBeNull();
        expect(await vaultReleaseFor('cc'.repeat(32))).toBeNull();
    });

    const dlOf = (tag: string) => `https://github.com/Privasys/enclave-vaults/releases/download/${tag}/mrenclave.txt`;

    it('checks a hinted release first, in one lookup, and keeps the answer', async () => {
        fetchMock.mockImplementation(async (url: string) => {
            if (url === 'https://api.github.com/repos/Privasys/enclave-vaults/releases/tags/vault-v0.50.0') {
                return { ok: true, json: async () => ({ tag_name: 'vault-v0.50.0', assets: [{ name: 'mrenclave.txt', browser_download_url: dlOf('vault-v0.50.0') }] }) };
            }
            if (url === dlOf('vault-v0.50.0')) return { ok: true, text: async () => 'ee'.repeat(32) + '\n' };
            return { ok: false, status: 404 };
        });
        expect((await vaultReleaseFor('ee'.repeat(32), 'vault-v0.50.0'))?.version).toBe('v0.50.0');
        expect(fetchMock).toHaveBeenCalledTimes(2);
        // Known from then on, with no hint and no request.
        forgetPublishedReleases();
        fetchMock.mockClear();
        expect((await vaultReleaseFor('ee'.repeat(32)))?.version).toBe('v0.50.0');
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('never lets a hint make a build pass', async () => {
        const answer = (over: Record<string, unknown>, body = 'ee'.repeat(32)) =>
            fetchMock.mockImplementation(async (url: string) => {
                if (url.includes('/releases/tags/')) {
                    return { ok: true, json: async () => ({ tag_name: 'vault-v0.50.0', assets: [{ name: 'mrenclave.txt', browser_download_url: dlOf('vault-v0.50.0') }], ...over }) };
                }
                if (url === dlOf('vault-v0.50.0')) return { ok: true, text: async () => body };
                // The full list knows no such build either.
                if (url.includes('/releases?')) return { ok: true, json: async () => [] };
                return { ok: false, status: 404 };
            });
        const build = 'ee'.repeat(32);
        // The release is another build, a draft, a prerelease, or its file is elsewhere.
        answer({}, 'dd'.repeat(32));
        expect(await vaultReleaseFor(build, 'vault-v0.50.0')).toBeNull();
        for (const over of [{ draft: true }, { prerelease: true }, { tag_name: 'vault-v0.51.0' },
            { assets: [{ name: 'mrenclave.txt', browser_download_url: 'https://example.com/mrenclave.txt' }] }]) {
            forgetPublishedReleases();
            answer(over);
            expect(await vaultReleaseFor(build, 'vault-v0.50.0')).toBeNull();
        }
        // A hint that is not a release tag is not looked up at all.
        forgetPublishedReleases();
        fetchMock.mockReset();
        fetchMock.mockImplementation(async (url: string) => (url.includes('/releases?') ? { ok: true, json: async () => [] } : { ok: false, status: 404 }));
        expect(await vaultReleaseFor(build, '../../../evil')).toBeNull();
        expect(fetchMock.mock.calls.every((c) => !String(c[0]).includes('/tags/'))).toBe(true);
    });

    it('throws when GitHub cannot be reached for a build not pinned', async () => {
        fetchMock.mockResolvedValue({ ok: false, status: 403 });
        await expect(vaultReleaseFor('dd'.repeat(32))).rejects.toThrow();
    });
});
