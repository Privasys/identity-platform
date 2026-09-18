// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The app_storage kind on the wire: an app asking to keep the holder's files in
 * its own storage, minted at a service_url the app names rather than at a
 * service the wallet resolves.
 *
 * The part that matters most is the host check. A service_url is a URL out of
 * a request, and posting a holder-authenticated call to a URL a request chose
 * is exactly what resolving by identity (S5) exists to prevent. It is safe only
 * on the host the wallet has just attested and read the ask from.
 */

jest.mock('../../modules/native-ratls/src/index', () => ({ makeRaTlsFetch: jest.fn() }));
jest.mock('@/services/platform-token', () => ({ getPlatformToken: jest.fn(async () => 'tok') }));
jest.mock('@/services/wallet-call', () => ({
    walletCallHeaders: jest.fn(async (method: string, path: string) => ({
        'X-Privasys-Wallet-Proof': `proof:${method}:${path}`,
    })),
}));

import { makeRaTlsFetch } from '../../modules/native-ratls/src/index';
import {
    CapabilityError,
    createCapability,
    expiryFor,
    fetchPendingCapability,
    isFolderBusy,
    isStaleTenantKey,
    listCapabilities,
    parsePendingCapability,
    revokeCapability,
} from '@/services/capabilities';

const raTls = makeRaTlsFetch as unknown as jest.Mock;

const HOST = 'privasystant.apps.test.privasys.org';
const SERVICE_URL = `https://${HOST}/__privasys/v1/capabilities`;
const NONCE = 'n'.repeat(64);

const ask = (over: Record<string, unknown> = {}) => ({
    nonce: NONCE,
    binding_pubkey: 'YmluZGluZy1rZXk=',
    resource_app: '3f6d1a0e-0000-4000-8000-000000000001',
    service_url: SERVICE_URL,
    capability: {
        kind: 'app_storage',
        permissions: ['read', 'write'],
        resource_label: 'Your working files',
        request: { label: 'Your working files' },
        options: { unattended: true },
    },
    ...over,
});

/** Every call the fake transport saw: url, method, headers, parsed body. */
let calls: { url: string; method: string; headers: Record<string, string>; body?: any }[] = [];

function answer(status: number, body: unknown) {
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    raTls.mockReturnValue(
        async (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => {
            calls.push({
                url,
                method: init?.method ?? 'GET',
                headers: init?.headers ?? {},
                body: init?.body ? JSON.parse(init.body) : undefined,
            });
            return {
                ok: status >= 200 && status < 300,
                status,
                json: async () => JSON.parse(text),
                text: async () => text,
            };
        },
    );
}

beforeEach(() => {
    calls = [];
    raTls.mockReset();
});

describe('the ask', () => {
    it('reads the kind, the service_url and the unattended option', () => {
        const p = parsePendingCapability(ask());
        expect(p.capability.kind).toBe('app_storage');
        expect(p.service_url).toBe(SERVICE_URL);
        expect(p.capability.options.unattended).toBe(true);
    });

    // It changes the words on the screen, so only a real boolean counts.
    it.each([['yes'], [1], [null], [undefined]])('does not take %p as unattended', (v) => {
        const a = ask();
        (a.capability as any).options = { unattended: v };
        expect(parsePendingCapability(a).capability.options.unattended).toBeUndefined();
    });

    it('treats a missing options object as no options', () => {
        const a = ask();
        delete (a.capability as any).options;
        expect(parsePendingCapability(a).capability.options).toEqual({});
    });

    it('drops a trailing slash so the revoke path is not doubled', () => {
        expect(parsePendingCapability(ask({ service_url: `${SERVICE_URL}/` })).service_url).toBe(SERVICE_URL);
    });

    // A user-authenticated call over anything but TLS, or carrying credentials
    // or a query, is not one the wallet makes.
    it.each([
        `http://${HOST}/__privasys/v1/capabilities`,
        `https://user:pw@${HOST}/__privasys/v1/capabilities`,
        `${SERVICE_URL}?to=elsewhere`,
        `${SERVICE_URL}#frag`,
        'not a url',
        42,
    ])('refuses %p as a service_url', (bad) => {
        expect(() => parsePendingCapability(ask({ service_url: bad }))).toThrow(CapabilityError);
    });

    it('has no service_url when the ask names none', () => {
        const a = ask();
        delete (a as any).service_url;
        expect(parsePendingCapability(a).service_url).toBeUndefined();
    });
});

describe('the host check', () => {
    it('accepts a service_url on the host the ask was read from', async () => {
        answer(200, ask());
        await expect(fetchPendingCapability(HOST, NONCE)).resolves.toMatchObject({ service_url: SERVICE_URL });
    });

    // The whole point. On any other host the request would be choosing where
    // the wallet posts a holder-authenticated call.
    it('refuses a service_url on any other host', async () => {
        answer(200, ask({ service_url: 'https://attacker.example.org/__privasys/v1/capabilities' }));
        await expect(fetchPendingCapability(HOST, NONCE)).rejects.toThrow(/host other than the one that asked/);
    });

    it('refuses a sibling subdomain too', async () => {
        answer(200, ask({ service_url: `https://evil.${HOST}/__privasys/v1/capabilities` }));
        await expect(fetchPendingCapability(HOST, NONCE)).rejects.toThrow(CapabilityError);
    });
});

describe('expiry', () => {
    // It stands until revoked; 0 is also the wire value for that.
    it('is none for app_storage', () => {
        expect(expiryFor('app_storage', 1_800_000_000_000)).toBe(0);
    });

    it('is unchanged for the other kinds', () => {
        expect(expiryFor('storage.folder', 1_800_000_000_000)).toBe(1_800_000_000 + 90 * 24 * 60 * 60);
    });
});

describe('where each call goes', () => {
    const pending = () => parsePendingCapability(ask());

    it('mints at the service_url, with the key, unattended and the instance proof', async () => {
        answer(201, {
            capability_id: 'hf_1',
            kind: 'app_storage',
            service_result: { path: '/data/holders/abc' },
        });
        const out = await createCapability({
            resourceHost: HOST,
            subjectAppId: '3f6d1a0e-0000-4000-8000-000000000001',
            pending: pending(),
            expiresUnix: 0,
            setup: { key_b64: 'KEY', unattended: true },
        });

        expect(out.status).toBe('granted');
        const [c] = calls;
        expect(c.method).toBe('POST');
        expect(c.url).toBe(SERVICE_URL);
        expect(c.headers.Authorization).toBe('Bearer tok');
        expect(c.headers['X-Privasys-Wallet-Proof']).toBe('proof:POST:/__privasys/v1/capabilities');
        expect(c.body.setup).toEqual({ key_b64: 'KEY', unattended: true });
        expect(c.body.expires_unix).toBe(0);
        expect(c.body.kind).toBe('app_storage');
    });

    // Signing the proof prompts for Face ID. A prompt merely to LOOK at your
    // own grants, every time a screen opens, would be hostile.
    it('lists at the service_url with the bearer only, no proof', async () => {
        answer(200, { capabilities: [{ capability_id: 'hf_1', kind: 'app_storage' }] });
        const held = await listCapabilities(HOST, SERVICE_URL);

        expect(held?.map((c) => c.capability_id)).toEqual(['hf_1']);
        expect(calls[0].url).toBe(SERVICE_URL);
        expect(calls[0].headers['X-Privasys-Wallet-Proof']).toBeUndefined();
    });

    it('revokes at service_url/{id}, with the proof bound to that path', async () => {
        answer(200, { status: 'closed_and_verified', at: 1 });
        await revokeCapability(HOST, 'hf_1', SERVICE_URL);

        const [c] = calls;
        expect(c.method).toBe('DELETE');
        expect(c.url).toBe(`${SERVICE_URL}/hf_1`);
        expect(c.headers['X-Privasys-Wallet-Proof']).toBe('proof:DELETE:/__privasys/v1/capabilities/hf_1');
    });

    // Nothing changes for services resolved by identity: no proof, which they
    // never asked for and which would add a Face ID prompt to every approval.
    it('leaves the resolved services exactly as they were', async () => {
        answer(200, { capability_id: 'cap-1' });
        const drive = parsePendingCapability({ ...ask(), service_url: undefined, capability: {
            kind: 'storage.folder', permissions: ['read'], resource_label: 'Harness', request: {},
        } });
        await createCapability({
            resourceHost: 'drive.example.org',
            subjectAppId: '3f6d1a0e-0000-4000-8000-000000000001',
            pending: drive,
            expiresUnix: 1,
        });
        expect(calls[0].url).toBe('https://drive.example.org/v1/capabilities');
        expect(calls[0].headers['X-Privasys-Wallet-Proof']).toBeUndefined();
    });
});

describe('the revoke answers', () => {
    it.each([[200], [410], [404]])('treats %p as the outcome asked for', async (status) => {
        answer(status, '');
        await expect(revokeCapability(HOST, 'hf_1', SERVICE_URL)).resolves.toBeUndefined();
    });

    // Files still open: nothing revoked, nothing wrong, try again.
    it('recognises 409 as a busy folder', async () => {
        answer(409, 'files still in use');
        const e = await revokeCapability(HOST, 'hf_1', SERVICE_URL).catch((x) => x);
        expect(isFolderBusy(e)).toBe(true);
    });

    // Drive's stale key is also a 409, and must not be mistaken for a busy
    // folder: they call for entirely different responses.
    it('does not mistake a stale vault key for a busy folder', async () => {
        answer(409, { code: 'vault_key_stale' });
        const e = await revokeCapability(HOST, 'hf_1', SERVICE_URL).catch((x) => x);
        expect(isFolderBusy(e)).toBe(false);
        expect(isStaleTenantKey(e)).toBe(true);
    });
});
