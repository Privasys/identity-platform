// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The holder's approval for a Drive to open their key with a new build.
 */

const mockRemember = jest.fn();
jest.mock('../stores/vaultApprovals', () => ({
    useVaultApprovalsStore: { getState: () => ({ remember: mockRemember }) },
}));
jest.mock('../services/platforms', () => ({ audienceFor: jest.fn(async () => 'privasys-platform-test') }));

const mockCalls: { url: string; init: { method?: string; headers: Record<string, string>; body?: string }; interactive: boolean; target?: string }[] = [];
let mockAnswers: { status: number; body?: unknown }[] = [];
jest.mock('../services/platform-token', () => ({
    callWithPlatformToken: jest.fn(async (call: (t: string) => Promise<Response>, opts: { interactive: boolean; target?: string }) => {
        const res = await call('wallet-platform-key');
        mockCalls[mockCalls.length - 1].interactive = opts.interactive;
        mockCalls[mockCalls.length - 1].target = opts.target;
        return { res, token: 'wallet-platform-key' };
    }),
}));

let mockExpiresAt: number | null = null;
jest.mock('../services/vault-approval-api', () => ({
    fetchVaultApproval: jest.fn(async () => (mockExpiresAt === null ? null : { expires_at: mockExpiresAt })),
}));

import { approvalNeeded, obtainApproval, refusalFor, requestBody } from '../services/drive-key-approval';

const APP = '02104572ca2f41e8ae2d24c0294e6f5e';
const HANDLE = `apps.privasys.org/${APP}/data/c5144d4b012d351cc3538d2fcda87f88/mek/v15`;
const approval = (over: Record<string, unknown> = {}) => ({
    binding_version: 2,
    operation: 'update_policy_from',
    handle: HANDLE,
    audience: 'privasys-platform-test',
    ttl_seconds: 300,
    new_policy: '{}',
    ...over,
});
const noWait = async () => undefined;

beforeEach(() => {
    mockRemember.mockClear();
    mockCalls.length = 0;
    mockAnswers = [];
    mockExpiresAt = null;
    (global as any).fetch = jest.fn(async (url: string, init: any) => {
        mockCalls.push({ url, init, interactive: false });
        const a = mockAnswers.shift() ?? { status: 500 };
        return { ok: a.status >= 200 && a.status < 300, status: a.status, json: async () => a.body };
    });
});

describe('what Drive answers', () => {
    it('is an approval to ask for only when it says so', () => {
        const body = JSON.stringify({ error: 'owner_approval_required: the key needs its rules updated', approval: approval() });
        expect(approvalNeeded(409, body)?.handle).toBe(HANDLE);
        expect(approvalNeeded(502, body)).toBeNull();
        expect(approvalNeeded(409, JSON.stringify({ error: 'restage_needed: no policy record' }))).toBeNull();
        expect(approvalNeeded(409, JSON.stringify({ error: 'measurement_approval_required' }))).toBeNull();
        expect(approvalNeeded(409, JSON.stringify({ error: 'owner_approval_required: x' }))).toBeNull();
        expect(approvalNeeded(409, 'not json')).toBeNull();
    });
});

describe('an approval the wallet will ask for', () => {
    it("is a change to the rules of the holder's key at that Drive", () => {
        expect(refusalFor(approval(), APP, 'privasys-platform-test')).toBeNull();
        expect(refusalFor(approval({ operation: 'update_policy' }), APP, 'privasys-platform-test')).toBeNull();
        expect(refusalFor(approval({ operation: 'policy-update', binding_version: undefined }), APP, 'privasys-platform-test')).toBeNull();
        // The app id as the control plane writes it, with dashes.
        expect(refusalFor(approval(), '02104572-ca2f-41e8-ae2d-24c0294e6f5e', 'privasys-platform-test')).toBeNull();
    });

    it('is never a deletion, an export, a new key or a promote', () => {
        for (const operation of ['delete', 'export', 'create', 'promote', 'app-policy', '']) {
            expect(refusalFor(approval({ operation }), APP, 'privasys-platform-test')).toMatch(/may not ask/);
        }
    });

    it("never names a key that is not the holder's key at this Drive", () => {
        const other = 'cf7a0d585468416884c341ebe0ce4025';
        for (const handle of [
            `apps.privasys.org/${other}/data/c5144d4b012d351cc3538d2fcda87f88/mek/v15`, // another Drive's
            `apps.privasys.org/${APP}/storage-kek/v4`, // the app's own key
            `apps.privasys.org/${APP}/registry-cred/default`,
            `apps.privasys.org/${APP}/data/c5144d4b012d351cc3538d2fcda87f88/mek/v15/../../x`,
            `${APP}/data/c5144d4b012d351cc3538d2fcda87f88/mek/v15`,
            '',
        ]) {
            expect(refusalFor(approval({ handle }), APP, 'privasys-platform-test')).toMatch(/not your key/);
        }
    });

    it('is addressed to the platform the Drive belongs to', () => {
        expect(refusalFor(approval({ audience: 'privasys-platform' }), APP, 'privasys-platform-test')).toMatch(/not addressed to this platform/);
        expect(refusalFor(approval({ audience: undefined }), APP, 'privasys-platform-test')).toMatch(/not addressed to this platform/);
    });
});

describe('asking privasys.id', () => {
    it('sends what Drive described, as the holder, shows the card, and returns the approval', async () => {
        mockAnswers = [
            { status: 200, body: { vault_op: 'op-1', push_registered: true } },
            { status: 202 },
            { status: 200, body: { access_token: 'approval-token' } },
        ];
        const a = approval();
        expect(await obtainApproval(a, 'https://api.developer.test.privasys.org', noWait)).toBe('approval-token');

        expect(mockCalls[0].url).toMatch(/\/fido2\/vault-approval\/begin$/);
        expect(mockCalls[0].init.method).toBe('POST');
        // What an approval of this kind has, and not how long Drive wanted it to live.
        const { ttl_seconds: _ttl, ...kept } = a;
        expect(JSON.parse(mockCalls[0].init.body!)).toEqual(kept);
        expect(mockCalls[0].init.headers.Authorization).toBe('Bearer wallet-platform-key');
        expect(mockCalls[0].interactive).toBe(true);
        expect(mockCalls[0].target).toBe('https://api.developer.test.privasys.org');
        expect(mockRemember).toHaveBeenCalledWith('op-1');
        expect(mockCalls[1].url).toMatch(/\/fido2\/vault-approval\/token\?challenge=op-1$/);
        // Waiting never prompts.
        expect(mockCalls[1].interactive).toBe(false);
    });

    it('stops when privasys.id refuses to open the request, and shows no card', async () => {
        mockAnswers = [{ status: 403 }];
        await expect(obtainApproval(approval(), 'x', noWait)).rejects.toThrow(/could not be asked for \(403\)/);
        expect(mockRemember).not.toHaveBeenCalled();
    });

    it('stops when the holder declines or the request lapses', async () => {
        mockAnswers = [{ status: 200, body: { vault_op: 'op-2' } }, { status: 202 }, { status: 410 }];
        await expect(obtainApproval(approval(), 'x', noWait)).rejects.toThrow(/declined or has lapsed/);
    });

    it('waits as long as privasys.id says the request lives, whatever Drive said', async () => {
        mockAnswers = [{ status: 200, body: { vault_op: 'op-3' } }, ...Array.from({ length: 10 }, () => ({ status: 202 }))];
        mockExpiresAt = Math.floor(Date.now() / 1000) + 6;
        await expect(obtainApproval(approval({ ttl_seconds: 86400 }), 'x', noWait)).rejects.toThrow(/not given in time/);
        // One request to open it, then three looks two seconds apart.
        expect(mockCalls).toHaveLength(4);
    });
});

describe('what is sent to privasys.id', () => {
    it('is only what an approval of this kind has', () => {
        const body = requestBody(
            approval({
                target: 't',
                policy_version: 3,
                members: ['a', 'b'],
                member_identities: ['x', 'y'],
                issuer_index: 0,
                current_policy: '{"a":1}',
                context: { app_name: 'Privasys Drive', summary: 's'.repeat(500), key_type: 'data', extra: 'no', app_id: 7 },
                // None of these is a field of a rules change.
                ttl_seconds: 86400,
                delete_after: 'apps.privasys.org/x/y',
                batch: [{ handle: 'other' }],
                cosign: true,
                redirect: 'https://elsewhere.example',
            }),
        );
        expect(Object.keys(body).sort()).toEqual(
            ['audience', 'binding_version', 'context', 'current_policy', 'handle', 'issuer_index', 'member_identities', 'members', 'new_policy', 'operation', 'policy_version', 'target'].sort(),
        );
        expect(body.context).toEqual({ app_name: 'Privasys Drive', summary: 's'.repeat(200), key_type: 'data' });
    });

    it('names no build for a v1 rules change', () => {
        const body = requestBody(approval({ operation: 'policy-update', binding_version: undefined, measurement_digest: 'abc' }));
        expect(body.measurement_digest).toBe('');
    });

    it('is nothing at all when a field is not what it should be', () => {
        expect(() => requestBody(approval({ members: 'a,b' }))).toThrow(/not well formed \(members\)/);
        expect(() => requestBody(approval({ policy_version: '3' }))).toThrow(/not well formed/);
        expect(() => requestBody(approval({ new_policy: { rules: [] } }))).toThrow(/not well formed/);
    });
});
