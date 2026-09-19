// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What this phone keeps of a service's setup answers, and what it gives back.
 */

const mockMemory = new Map<string, string>();
jest.mock('@/utils/storage', () => ({
    getItemAsync: jest.fn(async (k: string) => mockMemory.get(k) ?? null),
    setItemAsync: jest.fn(async (k: string, v: string) => {
        mockMemory.set(k, v);
    }),
    deleteItemAsync: jest.fn(async (k: string) => {
        mockMemory.delete(k);
    }),
}));

import {
    clearKeptSetups,
    forgetSetup,
    keepKey,
    keepSetup,
    keptSetup,
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
