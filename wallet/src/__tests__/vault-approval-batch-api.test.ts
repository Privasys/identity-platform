// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

jest.mock('../services/fido2', () => ({ signVaultAssertion: jest.fn(async () => ({ id: 'cred' })) }));
jest.mock('../services/devices', () => ({ myDeviceTag: jest.fn() }));
jest.mock('../services/app-resolve', () => ({ resolveApp: jest.fn() }));
jest.mock('../stores/auth', () => ({ useAuthStore: { getState: () => ({}) } }));

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { resolveApp } from '../services/app-resolve';
import { signVaultAssertion } from '../services/fido2';
import { approveVaultBatch, fetchVaultBatch, lookupVaultBatchAppName } from '../services/vault-approval-api';
import { verifyVaultBatch } from '../services/vault-approval-batch';
import type { Credential } from '../stores/auth';

const vector = JSON.parse(
    readFileSync(resolve(__dirname, '..', '..', '..', 'shared', 'vault-approval-batch-vectors.json'), 'utf8'),
);
const pending = () => ({
    batch_id: vector.batch_id,
    label: vector.label,
    exp: vector.exp,
    options: { publicKey: { challenge: vector.batch_id, rpId: 'privasys.id' } },
    entries: vector.entries,
});
const credential = { keyAlias: 'key', credentialId: 'cred', serverRpId: 'privasys.id' } as Credential;

const respond = (status: number, body: unknown) =>
    ({ ok: status < 400, status, json: async () => body, text: async () => JSON.stringify(body) }) as Response;
const fetchMock = jest.fn();

beforeEach(() => {
    fetchMock.mockReset();
    (signVaultAssertion as jest.Mock).mockClear();
    global.fetch = fetchMock;
});

describe('fetchVaultBatch', () => {
    it('returns a list that verifies', async () => {
        fetchMock.mockResolvedValue(respond(200, pending()));
        const found = await fetchVaultBatch(vector.batch_id);
        expect(found.kind).toBe('ok');
        expect(String(fetchMock.mock.calls[0][0])).toContain(`/fido2/vault-approval/batch/pending?challenge=${vector.batch_id}`);
    });

    it('refuses a list that does not', async () => {
        fetchMock.mockResolvedValue(respond(200, { ...pending(), label: 'Something else' }));
        await expect(fetchVaultBatch(vector.batch_id)).resolves.toEqual({ kind: 'refused', reason: 'binding' });
    });

    it('refuses an answer that is not JSON', async () => {
        fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => { throw new SyntaxError('no'); } });
        await expect(fetchVaultBatch(vector.batch_id)).resolves.toEqual({ kind: 'refused', reason: 'malformed' });
    });

    it('says when the batch is no longer waiting', async () => {
        fetchMock.mockResolvedValue(respond(404, {}));
        await expect(fetchVaultBatch(vector.batch_id)).resolves.toEqual({ kind: 'gone' });
    });

    it('sends nothing for an id that cannot be a batch', async () => {
        await expect(fetchVaultBatch('../../admin')).resolves.toEqual({ kind: 'refused', reason: 'binding' });
        expect(fetchMock).not.toHaveBeenCalled();
    });
});

describe('approveVaultBatch', () => {
    const batch = () => verifyVaultBatch(vector.batch_id, pending());

    it('signs the recomputed binding and posts the assertion', async () => {
        fetchMock.mockResolvedValue(respond(200, { status: 'approved', count: vector.entries.length }));
        await approveVaultBatch(batch(), credential);
        const options = (signVaultAssertion as jest.Mock).mock.calls[0][3];
        expect(options.challenge).toBe(vector.batch_id);
        const [url, init] = fetchMock.mock.calls[0];
        expect(String(url)).toContain(`/fido2/vault-approval/batch/complete?challenge=${vector.batch_id}`);
        expect(init.method).toBe('POST');
        expect(JSON.parse(init.body)).toEqual({ id: 'cred' });
    });

    it('fails when the identity provider refuses', async () => {
        fetchMock.mockResolvedValue(respond(400, { error: 'verification failed' }));
        await expect(approveVaultBatch(batch(), credential)).rejects.toThrow('400');
    });

    it('fails when the answer does not cover the whole list', async () => {
        fetchMock.mockResolvedValue(respond(200, { status: 'approved', count: 1 }));
        await expect(approveVaultBatch(batch(), credential)).rejects.toThrow('whole list');
    });
});

describe('lookupVaultBatchAppName', () => {
    const hex = '0123456789abcdef0123456789abcdef';
    const dashed = '01234567-89ab-cdef-0123-456789abcdef';

    it('names the app the handle identifies', async () => {
        (resolveApp as jest.Mock).mockResolvedValue({ app_id: dashed, name: 'drive', display_name: 'Drive' });
        await expect(lookupVaultBatchAppName(hex)).resolves.toBe('Drive');
    });

    it('ignores an answer about another app', async () => {
        (resolveApp as jest.Mock).mockResolvedValue({ app_id: 'ffffffff-89ab-cdef-0123-456789abcdef', name: 'other', display_name: 'Other' });
        await expect(lookupVaultBatchAppName(hex)).resolves.toBeNull();
    });

    it('names nothing when the control plane cannot be reached', async () => {
        (resolveApp as jest.Mock).mockRejectedValue(new Error('offline'));
        await expect(lookupVaultBatchAppName(hex)).resolves.toBeNull();
    });
});
