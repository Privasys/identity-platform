// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

jest.mock('../services/notify-seal', () => ({
    openSealedNotification: jest.fn(async (sealed: string, type: string) => {
        if (type !== 'approval') return null;
        if (sealed === 'good') return { approval: GOOD };
        return null;
    }),
}));
jest.mock('../services/platform-token', () => ({
    callWithPlatformToken: jest.fn(async (call: (t: string) => Promise<Response>) => ({ res: await call('tok'), token: 'tok' })),
}));
jest.mock('../services/attestation', () => ({ inspectAttestation: jest.fn(), attestEnclave: jest.fn() }));
jest.mock('../services/app-attest', () => ({ getAttestationServerToken: jest.fn(async () => 'as') }));
jest.mock('../stores/settings', () => ({ useSettingsStore: { getState: () => ({ verificationMode: 'deterministic' }) } }));
jest.mock('../services/fido2', () => ({ signVaultAssertion: jest.fn(async () => ({ id: 'c' })) }));
jest.mock('../services/attribute-approval-api', () => ({
    resolveStepUpCredential: jest.fn(() => ({ keyAlias: 'k', credentialId: 'c', serverRpId: 'privasys.id' })),
}));
jest.mock('../../modules/native-ratls/src/index', () => ({ makeRaTlsFetch: jest.fn() }));
jest.mock('../../modules/native-keys/src/index', () => ({ authenticateForSigning: jest.fn(async () => true) }));
jest.mock('expo-local-authentication', () => ({ authenticateAsync: jest.fn(async () => ({ success: true })) }));
jest.mock('react-native', () => ({ Platform: { OS: 'ios' } }));

import { formDigest } from '../services/app-form';
import { parseApproval } from '../services/approval';
import { answerApproval, confirmApprovalSource } from '../services/approval-answer';
import { attestEnclave, inspectAttestation } from '../services/attestation';
import { signVaultAssertion } from '../services/fido2';
import { readMessage } from '../stores/app-messages';
import { makeRaTlsFetch } from '../../modules/native-ratls/src/index';
import * as NativeKeys from '../../modules/native-keys/src/index';

const ACT = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
const GOOD =
    '{"v":1,"id":"dec_1","title":"Grant the auditor role",' +
    '"lines":[{"label":"Person","value":"A. Lovelace"}],' +
    '"act_digest":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","assurance":"device","callback":"/approvals/answer","ttl":300}';
const APP = '11111111-2222-3333-4444-555555555555';
const HOST = 'register.apps.test.privasys.org';

describe('parseApproval', () => {
    it('reads a well-formed approval and keeps its digest', () => {
        const a = parseApproval(GOOD)!;
        expect(a).toMatchObject({ id: 'dec_1', title: 'Grant the auditor role', actDigest: ACT, assurance: 'device', ttl: 300 });
        expect(a.lines).toEqual([{ label: 'Person', value: 'A. Lovelace' }]);
        expect(a.digest).toBe(formDigest(GOOD));
    });

    it.each([
        ['an unknown field', GOOD.replace('"ttl":300', '"ttl":300,"buttons":["Pay"]')],
        ['a bidi override in the title', GOOD.replace('Grant the', 'Grant‮the')],
        ['a newline in a value', GOOD.replace('A. Lovelace', 'A.\\nLovelace')],
        ['an uppercase digest', GOOD.replace(ACT, ACT.toUpperCase())],
        ['an assurance off the list', GOOD.replace('"device"', '"sms"')],
        ['a URL for a callback', GOOD.replace('"/approvals/answer"', '"https://evil.example/x"')],
        ['a ttl out of range', GOOD.replace('"ttl":300', '"ttl":5')],
        ['a line with an extra key', GOOD.replace('"value":"A. Lovelace"', '"value":"A. Lovelace","href":"/x"')],
    ])('refuses %s', (_n, s) => {
        expect(parseApproval(s)).toBeNull();
    });
});

describe('readMessage for an approval', () => {
    it('shows it only when its digest is the one the IdP recorded', async () => {
        const row = { id: 'm1', type: 'approval', kind: 'request', app_id: APP, sealed: 'good', expires_at: 2e9, created_at: 1 };
        const shown = await readMessage({ ...row, form_digest: formDigest(GOOD) });
        expect(shown?.approval?.id).toBe('dec_1');
        expect(shown?.expiresAt).toBe(2e9);
        const hidden = await readMessage({ ...row, form_digest: 'ff'.repeat(32) });
        expect(hidden?.approval).toBeUndefined();
    });
});

describe('confirmApprovalSource', () => {
    const approval = parseApproval(GOOD)!;
    const confirmWith = (status: number, body: unknown) =>
        (makeRaTlsFetch as jest.Mock).mockReturnValue(async () => ({ ok: status === 200, status, json: async () => body }));
    beforeEach(() => {
        (inspectAttestation as jest.Mock).mockResolvedValue({
            custom_oids: [{ oid: '1.3.6.1.4.1.65230.4.1', value_hex: APP.replace(/-/g, '') }],
            tee_type: 'tdx',
        });
        (attestEnclave as jest.Mock).mockResolvedValue({ status: 'verified', mode: 'deterministic', challenged: false, result: {} });
    });

    it('confirms when the app waits on this exact approval', async () => {
        confirmWith(200, { open: true, id: 'dec_1', approval_digest: approval.digest });
        await expect(confirmApprovalSource({ approval, appId: APP, appSlug: 'register', platformHost: HOST })).resolves.toMatchObject({ host: HOST });
    });

    it('refuses when the app confirms another digest', async () => {
        confirmWith(200, { open: true, id: 'dec_1', approval_digest: 'ff'.repeat(32) });
        await expect(confirmApprovalSource({ approval, appId: APP, appSlug: 'register', platformHost: HOST })).rejects.toMatchObject({ reason: 'not-confirmed' });
    });
});

describe('answerApproval', () => {
    const approval = parseApproval(GOOD)!;
    afterEach(() => jest.restoreAllMocks());
    const args = { messageId: 'm1', approval, appId: APP, host: HOST, decision: 'approve' as const, prompt: 'p', cancel: 'c' };

    function beginReturns(over: Record<string, unknown>) {
        jest.spyOn(global, 'fetch').mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({
                options: { publicKey: { challenge: 'c', allowCredentials: [{ type: 'public-key', id: 'c' }] } },
                app_id: APP, approval_id: 'dec_1', approval_digest: approval.digest, act_digest: ACT,
                assurance: 'device', decision: 'approve', ...over,
            }),
        } as unknown as Response);
    }

    it.each([
        ['another approval digest', { approval_digest: 'ff'.repeat(32) }],
        ['another act', { act_digest: 'ee'.repeat(32) }],
        ['another decision', { decision: 'decline' }],
        ['another assurance', { assurance: 'gov-presence' }],
        ['another app', { app_id: '99999999-2222-3333-4444-555555555555' }],
    ])('refuses to sign when the IdP would bind %s', async (_n, over) => {
        beginReturns(over);
        (signVaultAssertion as jest.Mock).mockClear();
        await expect(answerApproval(args)).rejects.toMatchObject({ reason: 'mismatch' });
        expect(signVaultAssertion).not.toHaveBeenCalled();
    });

    it('asks for a fresh biometric before signing, and stops when it is refused', async () => {
        beginReturns({});
        (NativeKeys.authenticateForSigning as jest.Mock).mockResolvedValueOnce(false);
        (signVaultAssertion as jest.Mock).mockClear();
        await expect(answerApproval(args)).rejects.toMatchObject({ reason: 'cancelled' });
        expect(NativeKeys.authenticateForSigning).toHaveBeenCalledWith('p');
        expect(signVaultAssertion).not.toHaveBeenCalled();
    });

    it('does not answer a gov-presence approval it cannot check', async () => {
        const gov = parseApproval(GOOD.replace('"device"', '"gov-presence"'))!;
        await expect(answerApproval({ ...args, approval: gov })).rejects.toMatchObject({ reason: 'unverified' });
    });
});
