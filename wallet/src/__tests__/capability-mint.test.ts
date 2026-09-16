// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What the wallet does with each answer the resource service can give when it
 * is asked to mint a capability.
 *
 * Three of them are ordinary outcomes rather than failures, and telling them
 * apart is the whole point: a question is not a refusal, a provider saying no
 * is not the service failing, and only the last of these may ever tell the
 * holder that access was not granted.
 */

jest.mock('../../modules/native-ratls/src/index', () => ({ makeRaTlsFetch: jest.fn() }));
jest.mock('@/services/platform-token', () => ({ getPlatformToken: jest.fn(async () => 'tok') }));

import { makeRaTlsFetch } from '../../modules/native-ratls/src/index';
import {
    createCapability,
    isProviderRefusal,
    isStaleTenantKey,
    parsePendingCapability,
    CapabilityError,
} from '@/services/capabilities';

const raTls = makeRaTlsFetch as unknown as jest.Mock;

const pending = () =>
    parsePendingCapability({
        nonce: 'a'.repeat(64),
        binding_pubkey: 'YmluZGluZy1rZXk=',
        resource_app: 'privasys-mail-connector',
        capability: {
            kind: 'mail.mailbox',
            permissions: ['read', 'write'],
            resource_label: 'me@example.org',
            request: { mailbox: 'me@example.org' },
        },
    });

/** The last body posted to the resource service, parsed. */
let posted: Record<string, unknown> = {};

function answer(status: number, body: unknown) {
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    raTls.mockReturnValue(async (_url: string, init?: { body?: string }) => {
        posted = JSON.parse(init?.body ?? '{}');
        return {
            ok: status >= 200 && status < 300,
            status,
            json: async () => JSON.parse(text),
            text: async () => text,
        };
    });
}

const mint = (setup?: Record<string, unknown>) =>
    createCapability({
        resourceHost: 'connector.apps.privasys.org',
        subjectAppId: '3f6d1a0e-0000-4000-8000-000000000001',
        pending: pending(),
        expiresUnix: 1_900_000_000,
        setup,
    });

beforeEach(() => {
    posted = {};
    raTls.mockReset();
});

describe('200', () => {
    it('grants, and carries the answers to the service and nowhere else', async () => {
        answer(200, { capability_id: 'cap-1', service_result: { mailbox_id: 'm1' } });
        const out = await mint({ user: 'me@example.org', password: 'pw' });

        expect(out.status).toBe('granted');
        if (out.status !== 'granted') return;
        expect(out.granted.capability_id).toBe('cap-1');
        expect(out.granted.service_result).toEqual({ mailbox_id: 'm1' });
        expect(posted.setup).toEqual({ user: 'me@example.org', password: 'pw' });
        // What was displayed, so the minted capability cannot be wider than
        // the one approved.
        expect(posted.permissions).toEqual(['read', 'write']);
    });

    it('sends no setup field at all when there was nothing to answer', async () => {
        answer(200, { capability_id: 'cap-2' });
        await mint(undefined);
        expect('setup' in posted).toBe(false);
    });
});

describe('428', () => {
    // A question, not a failure. It must not reach the path that tells the
    // holder access was not granted, because nothing has been refused.
    it('comes back as one more step rather than an error', async () => {
        answer(428, {
            elicit: {
                message: 'We could not find your mail server.',
                requestedSchema: {
                    type: 'object',
                    properties: { imap_host: { type: 'string', title: 'IMAP server' } },
                    required: ['imap_host'],
                },
            },
        });
        const out = await mint({ user: 'me@example.org', password: 'pw' });

        expect(out.status).toBe('incomplete');
        if (out.status !== 'incomplete') return;
        expect(out.requirement.message).toBe('We could not find your mail server.');
        expect(out.requirement.fields.map((f) => f.name)).toEqual(['imap_host']);
    });

    it('is an error when the service does not say what it wants', async () => {
        answer(428, { elicit: { message: 'more please' } });
        await expect(mint({})).rejects.toThrow(CapabilityError);
    });
});

describe('502', () => {
    // The provider behind the service said no. The holder edits the form and
    // tries again; nothing was granted and nothing was sealed.
    it('carries the service sentence, which is the only account of why', async () => {
        answer(502, { error: 'the mailbox refused these details: invalid credentials' });
        const e = await mint({ user: 'me@example.org', password: 'wrong' }).catch((x) => x);

        expect(isProviderRefusal(e)).toBe(true);
        expect(e.message).toBe('the mailbox refused these details: invalid credentials');
    });

    it('carries no sentence at all rather than a page of HTML', async () => {
        answer(502, '<html>Bad Gateway</html>');
        const e = await mint({}).catch((x) => x);
        expect(isProviderRefusal(e)).toBe(true);
        expect(e.message).toBe('');
    });
});

describe('everything else', () => {
    it('is a failure, with the status the holder can report', async () => {
        answer(403, { error: 'nope' });
        const e = await mint({}).catch((x) => x);
        expect(isProviderRefusal(e)).toBe(false);
        expect(e).toBeInstanceOf(CapabilityError);
        expect(e.status).toBe(403);
    });

    // Still recognised as the one failure the wallet can fix in place, rather
    // than being swallowed by the new outcomes above it.
    it('still recognises a stale vault key', async () => {
        answer(409, { code: 'vault_key_stale' });
        const e = await mint({}).catch((x) => x);
        expect(isStaleTenantKey(e)).toBe(true);
    });
});

describe('the setup a request declares', () => {
    // Minting without a form the wallet could not draw would send the service
    // an answer nobody gave.
    it('refuses the whole request when the wallet cannot draw it', () => {
        expect(() =>
            parsePendingCapability({
                nonce: 'a'.repeat(64),
                binding_pubkey: 'k',
                resource_app: 'svc',
                capability: {
                    kind: 'mail.mailbox',
                    permissions: ['read'],
                    resource_label: 'me@example.org',
                    request: {},
                },
                setup: {
                    message: 'Connect your mailbox.',
                    requestedSchema: { type: 'object', properties: { port: { type: 'integer' } } },
                },
            }),
        ).toThrow(CapabilityError);
    });

    it('is read on to the pending request when it can', () => {
        const p = parsePendingCapability({
            nonce: 'a'.repeat(64),
            binding_pubkey: 'k',
            resource_app: 'svc',
            capability: {
                kind: 'mail.mailbox',
                permissions: ['read'],
                resource_label: 'me@example.org',
                request: {},
            },
            setup: {
                message: 'Connect your mailbox.',
                requestedSchema: {
                    type: 'object',
                    properties: { password: { type: 'string' } },
                    required: ['password'],
                },
                secrets: ['password'],
            },
        });
        expect(p.setup?.fields[0].kind).toBe('secret');
        expect(p.setup?.prerequisites).toEqual([]);
    });
});
