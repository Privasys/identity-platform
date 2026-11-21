// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The verifier is upgraded under a running wallet: the build the platform
 * publishes is read afresh, not kept from the wallet's first call.
 */

const mockInspect = jest.fn();
const mockAttestEnclave = jest.fn(async () => ({ status: 'verified' }));
const mockPost = jest.fn(async () => ({ status: 200, body: JSON.stringify({ token: 'tok' }) }));

jest.mock('expo-crypto', () => ({}));
jest.mock('@/services/app-attest', () => ({ getAttestationServerToken: async () => 't' }));
jest.mock('@/services/attestation', () => ({
    inspectAttestation: (...a: unknown[]) => mockInspect(...a),
    attestEnclave: (...a: unknown[]) => mockAttestEnclave(...(a as [])),
}));
jest.mock('@/services/encauth', () => ({ derToRawEcdsa: (b: Uint8Array) => b }));
jest.mock('@/services/wia', () => ({ ensureWia: async () => 'wia' }));
jest.mock('@/stores/profile', () => ({ useProfileStore: { getState: () => ({ profile: null }) } }));
jest.mock('@/stores/settings', () => ({ useSettingsStore: { getState: () => ({ verificationMode: 'strict' }) } }));
jest.mock('../../modules/native-keys/src/index', () => ({
    getPublicKey: async () => ({ publicKey: 'pub' }),
    sign: async () => ({ signature: 'AA' }),
}));
jest.mock('../../modules/native-ratls/src/index', () => ({ post: (...a: unknown[]) => mockPost(...(a as [])) }));

import { disclose, resetAttributeVerifier } from '@/services/attribute-verifier';

const IMAGE_OID = '1.3.6.1.4.1.65230.4.2';
const PROOF = `x.${Buffer.from(JSON.stringify({ jti: 'j1' })).toString('base64url')}.y`;

let published: string;
const leaf = (digest: string) => ({ tee_type: 'tdx', custom_oids: [{ oid: IMAGE_OID, value_hex: digest }] });

beforeEach(() => {
    resetAttributeVerifier();
    jest.clearAllMocks();
    published = 'aa';
    (global as any).fetch = jest.fn(async () => ({
        ok: true,
        json: async () => ({ hostname: 'verifier.example:443', image_digest: published }),
    }));
});

describe('attribute verifier channel', () => {
    it('follows an upgrade made while the wallet runs', async () => {
        mockInspect.mockResolvedValue(leaf('aa'));
        await expect(disclose(PROOF, 'rp', 'sub', 'n')).resolves.toBe('tok');

        // The verifier is upgraded; the wallet's next attestation is due.
        published = 'bb';
        mockInspect.mockResolvedValue(leaf('bb'));
        jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 11 * 60 * 1000);
        await expect(disclose(PROOF, 'rp', 'sub', 'n')).resolves.toBe('tok');
        (Date.now as jest.Mock).mockRestore();
    });

    it('reads the published build once more when an upgrade lands between the two reads', async () => {
        mockInspect.mockResolvedValue(leaf('bb'));
        (global as any).fetch = jest
            .fn()
            .mockResolvedValueOnce({ ok: true, json: async () => ({ hostname: 'verifier.example', image_digest: 'aa' }) })
            .mockResolvedValueOnce({ ok: true, json: async () => ({ hostname: 'verifier.example', image_digest: 'bb' }) });
        await expect(disclose(PROOF, 'rp', 'sub', 'n')).resolves.toBe('tok');
    });

    it('refuses an enclave that is not the published build, and sends nothing', async () => {
        mockInspect.mockResolvedValue(leaf('cc'));
        await expect(disclose(PROOF, 'rp', 'sub', 'n')).rejects.toThrow('not the published build');
        expect(mockPost).not.toHaveBeenCalled();
    });
});
