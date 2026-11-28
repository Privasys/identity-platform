// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * An import tries the verifier again when it is briefly unavailable: freely
 * up to the challenge, once more at most after the device key has signed
 * (each signature asks for the holder's biometric), never after a refusal
 * or a cancelled prompt.
 */

const mockPost = jest.fn();
const mockSign = jest.fn(async () => ({ signature: 'AA' }));

jest.mock('expo-crypto', () => ({}));
jest.mock('@/services/app-attest', () => ({ getAttestationServerToken: async () => 't' }));
jest.mock('@/services/attestation', () => ({
    inspectAttestation: async () => ({ tee_type: 'tdx', custom_oids: [{ oid: '1.3.6.1.4.1.65230.4.2', value_hex: 'aa' }] }),
    attestEnclave: async () => ({ status: 'verified' }),
}));
jest.mock('@/services/encauth', () => ({ derToRawEcdsa: (b: Uint8Array) => b }));
jest.mock('@/services/wia', () => ({ ensureWia: async () => 'wia' }));
jest.mock('@/stores/profile', () => ({
    useProfileStore: { getState: () => ({ profile: { pairwiseSeed: '11'.repeat(32) } }) },
}));
jest.mock('@/stores/settings', () => ({ useSettingsStore: { getState: () => ({ verificationMode: 'strict' }) } }));
jest.mock('../../modules/native-keys/src/index', () => ({
    getPublicKey: async () => ({ publicKey: 'pub' }),
    sign: (...a: unknown[]) => mockSign(...(a as [])),
}));
jest.mock('../../modules/native-ratls/src/index', () => ({ post: (...a: unknown[]) => mockPost(...a) }));

import { attest, resetAttributeVerifier } from '@/services/attribute-verifier';

const SALT = 'AAAAAAAAAAAAAAAAAAAAAA';
const PROOFS = [{ attr: 'email', value: 'a@example.com', method: 'proven', source: 'google', label: null, proof: 'p' }];

const ok = (body: unknown) => ({ status: 200, body: JSON.stringify(body) });
const fail = (status: number) => ({ status, body: JSON.stringify({ error: `HTTP ${status}` }) });

/** Route the verifier's two calls; each list is consumed in order, its last entry repeated. */
function verifier(challenges: unknown[], attests: unknown[]) {
    mockPost.mockImplementation(async (_h: string, _p: number, path: string) => {
        const list = path === '/challenge' ? challenges : attests;
        const next = list.length > 1 ? list.shift() : list[0];
        if (next instanceof Error) throw next;
        return next;
    });
}

const attestCalls = () => mockPost.mock.calls.filter((c) => c[2] === '/attest').length;

beforeEach(() => {
    resetAttributeVerifier();
    jest.clearAllMocks();
    jest.spyOn(global, 'setTimeout').mockImplementation(((fn: () => void) => {
        fn();
        return 0;
    }) as any);
    (global as any).fetch = jest.fn(async () => ({
        ok: true,
        json: async () => ({ hostname: 'verifier.example', image_digest: 'aa' }),
    }));
});

afterEach(() => jest.restoreAllMocks());

describe('attest retries', () => {
    it('retries reaching the verifier without asking for a signature', async () => {
        verifier([new Error('network'), fail(503), ok({ challenge: 'c' })], [ok({ proofs: PROOFS })]);
        await expect(attest('oidc_id_token', { id_token: 't' }, SALT, { attempts: 3 })).resolves.toEqual(PROOFS);
        expect(mockSign).toHaveBeenCalledTimes(1);
    });

    it('sends the attest again once when the verifier was unavailable', async () => {
        verifier([ok({ challenge: 'c' })], [fail(503), ok({ proofs: PROOFS })]);
        await expect(attest('oidc_id_token', { id_token: 't' }, SALT, { attempts: 3 })).resolves.toEqual(PROOFS);
        expect(mockSign).toHaveBeenCalledTimes(2);
    });

    it('signs at most twice, however many attempts are left', async () => {
        verifier([ok({ challenge: 'c' })], [fail(503)]);
        await expect(attest('oidc_id_token', { id_token: 't' }, SALT, { attempts: 3 })).rejects.toThrow('HTTP 503');
        expect(mockSign).toHaveBeenCalledTimes(2);
        expect(attestCalls()).toBe(2);
    });

    it('takes a refusal as final', async () => {
        verifier([ok({ challenge: 'c' })], [fail(400)]);
        await expect(attest('oidc_id_token', { id_token: 't' }, SALT, { attempts: 3 })).rejects.toThrow('HTTP 400');
        expect(attestCalls()).toBe(1);
    });

    it('never asks again after the holder cancelled the prompt', async () => {
        verifier([ok({ challenge: 'c' })], [ok({ proofs: PROOFS })]);
        mockSign.mockRejectedValueOnce(new Error('cancelled'));
        await expect(attest('oidc_id_token', { id_token: 't' }, SALT, { attempts: 3 })).rejects.toThrow('cancelled');
        expect(mockSign).toHaveBeenCalledTimes(1);
        expect(attestCalls()).toBe(0);
    });

    it('tries once by default', async () => {
        verifier([fail(503)], [ok({ proofs: PROOFS })]);
        await expect(attest('oidc_id_token', { id_token: 't' }, SALT)).rejects.toThrow('HTTP 503');
        expect(mockPost).toHaveBeenCalledTimes(1);
    });
});
