// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What this phone keeps of a service's setup answers, and what it gives back.
 */

const mockMemory = new Map<string, string>();
// The device store throws on a key outside [\w.-]; so does this one, or a key
// spelling that works only in tests ships again (v1 carried ":").
const mockValid = (k: string) => {
    if (!/^[\w.-]+$/.test(k)) throw new Error(`Invalid key provided to SecureStore: ${k}`);
};
jest.mock('@/utils/storage', () => ({
    getItemAsync: jest.fn(async (k: string) => {
        mockValid(k);
        return mockMemory.get(k) ?? null;
    }),
    setItemAsync: jest.fn(async (k: string, v: string) => {
        mockValid(k);
        mockMemory.set(k, v);
    }),
    deleteItemAsync: jest.fn(async (k: string) => {
        mockValid(k);
        mockMemory.delete(k);
    }),
}));

import {
    clearKeptSetups,
    forgetSetup,
    keepKey,
    keepSetup,
    keptSetup,
    keptSetups,
    labelOf,
    nonSecretAnswers,
    resupplyPayload,
} from '@/services/setup-keep';

const SERVICE = '7958ba28-a8d4-40f1-873a-925c15b87aa8';

beforeEach(() => mockMemory.clear());

describe('the key', () => {
    it('is the same for a dashed and a bare app id', () => {
        expect(keepKey(SERVICE, 'mail.mailbox')).toBe(
            keepKey('7958ba28a8d440f1873a925c15b87aa8', 'mail.mailbox'),
        );
    });
    it('refuses anything that is not an app id', () => {
        expect(() => keepKey('mail-connector.apps.privasys.org', 'mail.mailbox')).toThrow();
    });
});

describe('keep and re-supply', () => {
    it('keeps the answers, names the secrets and labels by the first non-secret', async () => {
        await keepSetup({
            serviceAppId: SERVICE,
            kind: 'mail.mailbox',
            answers: { user: 'alice@example.org', password: 'hunter2' },
            secrets: ['password'],
            secretLabels: ['App password'],
            now: 1000,
        });
        const k = await keptSetup(SERVICE, 'mail.mailbox');
        expect(k).toEqual({
            account: '',
            answers: { user: 'alice@example.org', password: 'hunter2' },
            secrets: ['password'],
            secretLabels: ['App password'],
            label: 'alice@example.org',
            kept: undefined,
            keptAt: 1000,
        });
        expect(resupplyPayload(k!)).toEqual({ user: 'alice@example.org', password: 'hunter2' });
    });

    it('never prefills a secret into a form', async () => {
        await keepSetup({
            serviceAppId: SERVICE,
            kind: 'mail.mailbox',
            answers: { user: 'alice@example.org', password: 'hunter2', host: 'imap.example.org:993' },
            secrets: ['password'],
        });
        expect(nonSecretAnswers((await keptSetup(SERVICE, 'mail.mailbox'))!)).toEqual({
            user: 'alice@example.org',
            host: 'imap.example.org:993',
        });
    });

    it("carries the service's kept values back under `kept`, never among the answers", async () => {
        await keepSetup({
            serviceAppId: SERVICE,
            kind: 'calendar.events',
            answers: { grant: 'code-123', kept: { stale: true } },
            secrets: ['grant'],
            kept: { refresh: 'r-1' },
        });
        const k = (await keptSetup(SERVICE, 'calendar.events'))!;
        expect(k.answers).toEqual({ grant: 'code-123' });
        expect(resupplyPayload(k)).toEqual({ grant: 'code-123', kept: { refresh: 'r-1' } });
        expect(nonSecretAnswers(k)).toEqual({});
    });

    it('is nothing for a service that was never kept, or for another kind', async () => {
        await keepSetup({ serviceAppId: SERVICE, kind: 'mail.mailbox', answers: { user: 'a' }, secrets: [] });
        expect(await keptSetup(SERVICE, 'calendar.events')).toBeNull();
        expect(await keptSetup('0123456789abcdef0123456789abcdef', 'mail.mailbox')).toBeNull();
    });

    it('labels by the first non-secret string only', () => {
        expect(labelOf({ password: 'x', user: 'bob@example.org' }, ['password'])).toBe('bob@example.org');
        expect(labelOf({ password: 'x' }, ['password'])).toBeUndefined();
    });
});

describe('forget', () => {
    it('drops one service and kind and leaves the others', async () => {
        await keepSetup({ serviceAppId: SERVICE, kind: 'mail.mailbox', answers: { user: 'a' }, secrets: [] });
        await keepSetup({ serviceAppId: SERVICE, kind: 'calendar.events', answers: { user: 'b' }, secrets: [] });
        await forgetSetup(SERVICE, 'mail.mailbox');
        expect(await keptSetup(SERVICE, 'mail.mailbox')).toBeNull();
        expect((await keptSetup(SERVICE, 'calendar.events'))?.answers).toEqual({ user: 'b' });
    });

    it('the wipe clears everything kept, through the index', async () => {
        await keepSetup({ serviceAppId: SERVICE, kind: 'mail.mailbox', answers: { user: 'a' }, secrets: [] });
        await keepSetup({ serviceAppId: SERVICE, kind: 'calendar.events', answers: { user: 'b' }, secrets: [] });
        await clearKeptSetups();
        expect(mockMemory.size).toBe(0);
    });
});

describe('several accounts at one service', () => {
    const keep = (account: string, now: number) =>
        keepSetup({
            serviceAppId: SERVICE,
            kind: 'mail.mailbox',
            account,
            answers: { user: account },
            secrets: [],
            kept: { refresh_token: `rt-${account}` },
            now,
        });

    it('keeps each account apart, under keys the device store accepts', async () => {
        await keep('Me@Home.example', 1000);
        await keep('work@corp.example', 2000);
        for (const k of mockMemory.keys()) expect(k).toMatch(/^[\w.-]+$/);
        const all = await keptSetups(SERVICE, 'mail.mailbox');
        expect(all.map((k) => k.account)).toEqual(['work@corp.example', 'me@home.example']);
        expect((await keptSetup(SERVICE, 'mail.mailbox', 'ME@home.example'))?.kept).toEqual({
            refresh_token: 'rt-Me@Home.example',
        });
    });

    it('with no account named, gives the one kept most recently', async () => {
        await keep('me@home.example', 1000);
        await keep('work@corp.example', 2000);
        expect((await keptSetup(SERVICE, 'mail.mailbox'))?.account).toBe('work@corp.example');
    });

    it('forgets one account and leaves the other', async () => {
        await keep('me@home.example', 1000);
        await keep('work@corp.example', 2000);
        await forgetSetup(SERVICE, 'mail.mailbox', 'me@home.example');
        expect((await keptSetups(SERVICE, 'mail.mailbox')).map((k) => k.account)).toEqual(['work@corp.example']);
        await forgetSetup(SERVICE, 'mail.mailbox');
        expect(await keptSetups(SERVICE, 'mail.mailbox')).toEqual([]);
    });
});
