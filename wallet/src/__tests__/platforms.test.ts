// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A key sent to a host is one for that host's platform, as privasys.id
 * publishes the platforms. The wallet names none itself.
 */

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
jest.mock('@/services/fido2', () => ({ authenticate: jest.fn(async () => ({ sessionToken: 'sess' })) }));
jest.mock('@/services/privasys-id', () => ({ ensurePrivasysSession: jest.fn(async () => ({ sessionToken: 'sess' })) }));

import { audienceFor, forgetPlatforms } from '@/services/platforms';
import { callWithPlatformToken, clearPlatformToken, tokenForHost } from '@/services/platform-token';
import { useAuthStore } from '@/stores/auth';

const { mockStore } = jest.requireMock('@/utils/storage') as { mockStore: Record<string, string> };

const PUBLISHED = {
    platforms: [
        { audience: 'privasys-platform' },
        { audience: 'aud-b', domains: ['b.example.org'] },
        { audience: 'aud-c', domains: ['deep.b.example.org', 'c.example.net'] },
    ],
};

let platformsReply: () => Promise<any>;
const minted: string[] = [];

beforeAll(() => {
    useAuthStore.setState({
        credentials: [
            {
                credentialId: 'c1', rpId: 'privasys.id', origin: 'privasys.id', keyAlias: 'k',
                userHandle: 'h', userName: 'n', registeredAt: 1,
            },
        ],
    } as any);
    (global as any).fetch = jest.fn(async (url: string, init: any) => {
        if (url.endsWith('/wallet/platforms')) return platformsReply();
        const body = JSON.parse(init.body);
        minted.push(body.audience);
        return { ok: true, json: async () => ({ token: `key-${body.audience}`, expires_at: Math.floor(Date.now() / 1000) + 30 * 86400 }) };
    });
});

beforeEach(() => {
    forgetPlatforms();
    for (const k of Object.keys(mockStore)) delete mockStore[k];
    minted.length = 0;
    platformsReply = async () => ({ ok: true, json: async () => PUBLISHED });
});

it('takes the audience of the platform claiming the host, the most specific domain winning', async () => {
    expect(await audienceFor('https://api.b.example.org/api/v1/x')).toBe('aud-b');
    expect(await audienceFor('b.example.org')).toBe('aud-b');
    expect(await audienceFor('App.Deep.B.Example.Org:443')).toBe('aud-c');
    expect(await audienceFor('c.example.net')).toBe('aud-c');
    // No platform claims these: a look-alike, a parent, anything else.
    expect(await audienceFor('notb.example.org')).toBe('privasys-platform');
    expect(await audienceFor('b.example.org.evil.test')).toBe('privasys-platform');
    expect(await audienceFor('example.org')).toBe('privasys-platform');
    expect(await audienceFor('https://privasys.id')).toBe('privasys-platform');
    expect((global as any).fetch).toHaveBeenCalledTimes(1);
});

it('keeps the list for a launch when privasys.id cannot be reached', async () => {
    await audienceFor('b.example.org');
    forgetPlatforms();
    platformsReply = async () => ({ ok: false, status: 503 });
    expect(await audienceFor('x.b.example.org')).toBe('aud-b');
});

it('sends no key to a named host while the platforms have never been read', async () => {
    platformsReply = async () => ({ ok: false, status: 404 });
    await expect(tokenForHost('x.b.example.org')).rejects.toThrow();
    const call = jest.fn();
    expect(await callWithPlatformToken(call, { interactive: false, target: 'https://x.b.example.org' })).toBeNull();
    await expect(callWithPlatformToken(call, { interactive: true, target: 'https://x.b.example.org' })).rejects.toThrow();
    expect(call).not.toHaveBeenCalled();
    expect(minted).toEqual([]);
});

it('refuses a list that is not one, rather than read part of it', async () => {
    for (const bad of [
        {},
        { platforms: [{ audience: 'a b', domains: ['b.example.org'] }] },
        { platforms: [{ audience: 'aud-b', domains: ['*.example.org'] }] },
        { platforms: [{ audience: 'aud-b', domains: 'b.example.org' }] },
    ]) {
        forgetPlatforms();
        platformsReply = async () => ({ ok: true, json: async () => bad });
        await expect(audienceFor('b.example.org')).rejects.toThrow();
    }
});

it('mints and caches each platform its own key, and clears them all', async () => {
    expect(await tokenForHost('x.b.example.org')).toBe('key-aud-b');
    expect(await tokenForHost('other.example.com')).toBe('key-privasys-platform');
    expect(await tokenForHost('y.b.example.org')).toBe('key-aud-b');
    const made = await callWithPlatformToken(async () => ({ status: 200 }) as Response, {
        interactive: true,
        target: 'https://api.b.example.org',
    });
    expect(made?.token).toBe('key-aud-b');
    expect(minted).toEqual(['aud-b', 'privasys-platform']);
    await clearPlatformToken();
    expect(Object.keys(mockStore).filter((k) => k.startsWith('privasys.platform-token'))).toEqual([]);
});

describe('the platform behind a vault billing id', () => {
    const { billingPlatform } = require('@/services/platforms');
    const { createHash } = require('crypto');
    const sha = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');
    const implicit = (aud: string) => sha(`privasys-billing-implicit-v0\nhttps://privasys.id\n${aud}`);

    it('is the vault vector for the test audience', () => {
        const v = require('../../../idp/internal/vaultbinding/testdata/v2_vectors.json').billing_id_implicit_v0;
        expect(implicit(v.audience)).toBe(v.billing_id);
    });

    it('is production, a published platform by its domain, or unknown', async () => {
        expect(await billingPlatform([implicit('privasys-platform')])).toEqual({ kind: 'default' });
        expect(await billingPlatform([implicit('aud-b')])).toEqual({ kind: 'named', domain: 'b.example.org' });
        expect(await billingPlatform([implicit('aud-zzz')])).toEqual({ kind: 'unknown' });
        expect(await billingPlatform([implicit('privasys-platform'), implicit('aud-b')])).toEqual({ kind: 'unknown' });
        expect(await billingPlatform([])).toEqual({ kind: 'unknown' });
    });
});
