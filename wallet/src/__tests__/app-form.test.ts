// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

jest.mock('../services/notify-seal', () => ({
    openSealedNotification: jest.fn(async (sealed: string, type: string) => {
        if (type !== 'app-form') return null;
        if (sealed === 'good') return { kind: 'request', form: GOOD };
        return null;
    }),
}));
jest.mock('../services/platform-token', () => ({ getCachedPlatformToken: jest.fn(async () => 'tok') }));
jest.mock('../services/attestation', () => ({ inspectAttestation: jest.fn(), attestEnclave: jest.fn() }));
jest.mock('../services/app-attest', () => ({ getAttestationServerToken: jest.fn(async () => 'as') }));
jest.mock('../stores/settings', () => ({ useSettingsStore: { getState: () => ({ verificationMode: 'deterministic' }) } }));
jest.mock('../services/fido2', () => ({ signVaultAssertion: jest.fn(async () => ({ id: 'c' })) }));
jest.mock('../services/attribute-approval-api', () => ({
    resolveStepUpCredential: jest.fn(() => ({ keyAlias: 'k', credentialId: 'c', serverRpId: 'privasys.id' })),
}));
jest.mock('../../modules/native-ratls/src/index', () => ({ makeRaTlsFetch: jest.fn() }));

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { formDigest, parseForm } from '../services/app-form';
import { answerForm, AnswerError, confirmFormSource, hostIsApp, removedWhenRefused } from '../services/app-form-answer';
import { attestEnclave, inspectAttestation } from '../services/attestation';
import { makeRaTlsFetch } from '../../modules/native-ratls/src/index';
import { signVaultAssertion } from '../services/fido2';
import { readMessage } from '../stores/app-messages';

const GOOD =
    '{"v":1,"id":"req_1","title":"Access to a shared file",' +
    '"blocks":[{"type":"attributes","values":{"name":"Ada","email":"ada@example.org","not_a_key":"x"}},' +
    '{"type":"fields","items":[{"label":"File","value":"Q3 report.pdf"}]},' +
    '{"type":"text","text":"Ada opened your link.\\nShe asks to read it."},{"type":"divider"}],' +
    '"actions":[{"id":"approve","kind":"approve"},{"id":"deny","kind":"deny"}],' +
    '"callback":"/api/answer","link":"/#requests"}';

describe('parseForm', () => {
    it('reads a well-formed form, and shows only attributes it can label', () => {
        const f = parseForm(GOOD)!;
        expect(f.id).toBe('req_1');
        expect(f.actions.map((a) => a.kind)).toEqual(['approve', 'deny']);
        const attrs = f.blocks.find((b) => b.type === 'attributes');
        expect(attrs).toEqual({ type: 'attributes', values: [['name', 'Ada'], ['email', 'ada@example.org']] });
        expect(f.digest).toBe(bytesToHex(sha256(new TextEncoder().encode(GOOD))));
    });

    const swap = (a: string, b: string) => GOOD.replace(a, b);
    it.each([
        ['unknown component', swap('{"type":"divider"}', '{"type":"html","html":"<b>x</b>"}')],
        ['extra key on a block', swap('{"type":"divider"}', '{"type":"divider","onPress":"x"}')],
        ['app-written button label', swap('{"id":"deny","kind":"deny"}', '{"id":"deny","kind":"deny","label":"Approve"}')],
        ['button kind off the list', swap('"kind":"deny"', '"kind":"wipe"')],
        ['the same kind twice', swap('"kind":"deny"', '"kind":"approve"')],
        ['callback to another host', swap('"/api/answer"', '"//evil.example/x"')],
        ['link as a script', swap('"/#requests"', '"javascript:alert(1)"')],
        ['bidi override', swap('Access to', 'Access ‮to')],
        ['zero-width space', swap('Q3 report', 'Q3​report')],
        ['newline in a field', swap('Q3 report', 'Q3\\nreport')],
        ['too many actions', swap('{"id":"deny","kind":"deny"}', '{"id":"deny","kind":"deny"},{"id":"a","kind":"accept"},{"id":"c","kind":"confirm"}')],
        ['not JSON', 'not json'],
    ])('refuses %s', (_name, form) => {
        expect(form).not.toBe(GOOD);
        expect(parseForm(form)).toBeNull();
    });
});

describe('readMessage', () => {
    it('shows a form only when its digest is the one the IdP recorded', async () => {
        const ok = await readMessage({ id: 'm1', type: 'app-form', kind: 'request', sealed: 'good', form_digest: formDigest(GOOD) });
        expect(ok?.form?.id).toBe('req_1');
        const tampered = await readMessage({ id: 'm2', type: 'app-form', kind: 'request', sealed: 'good', form_digest: 'ff'.repeat(32) });
        expect(tampered?.form).toBeUndefined();
        const sealedForAnotherType = await readMessage({ id: 'm3', type: 'app-message', sealed: 'good' });
        expect(sealedForAnotherType?.type).toBe('app-message');
    });
});

describe('answerForm', () => {
    const form = parseForm(GOOD)!;
    const APP = '11111111-2222-3333-4444-555555555555';
    afterEach(() => jest.restoreAllMocks());

    function beginReturns(over: Record<string, unknown>) {
        jest.spyOn(global, 'fetch').mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({
                options: { publicKey: { challenge: 'c', allowCredentials: [{ type: 'public-key', id: 'c' }] } },
                app_id: APP, form_id: form.id, form_digest: form.digest, action: 'approve', ...over,
            }),
        } as unknown as Response);
    }

    it.each([
        ['a different digest', { form_digest: 'ff'.repeat(32) }],
        ['a different form', { form_id: 'other' }],
        ['a different action', { action: 'deny' }],
        ['a different app', { app_id: '99999999-2222-3333-4444-555555555555' }],
    ])('refuses to sign when the IdP would bind %s', async (_name, over) => {
        beginReturns(over);
        (signVaultAssertion as jest.Mock).mockClear();
        await expect(answerForm({ messageId: 'm1', form, appId: APP, host: 'drive.apps.privasys.org', action: 'approve' })).rejects.toMatchObject({ reason: 'mismatch' });
        expect(signVaultAssertion).not.toHaveBeenCalled();
    });

    it('never offers an action the form does not have', async () => {
        await expect(answerForm({ messageId: 'm1', form, appId: APP, host: 'drive.apps.privasys.org', action: 'wipe' })).rejects.toBeInstanceOf(AnswerError);
    });
});

describe('ANSWER_HOST', () => {
    it('admits only an app platform hostname', () => {
        const { ANSWER_HOST } = jest.requireActual('../services/app-form-answer');
        for (const ok of ['drive-demo.apps.test.privasys.org', 'privasys-drive.apps.privasys.org']) {
            expect(ANSWER_HOST.test(ok)).toBe(true);
        }
        for (const bad of [
            'drive.test.privasys.org',
            'a.b.apps.privasys.org',
            'drive.apps.privasys.org:8443',
            'drive.apps.privasys.org.evil.example',
            'driveXappsXprivasysXorg',
            'drive.appsxprivasys.org',
            'evil.example',
            '-drive.apps.privasys.org',
            'DRIVE.apps.privasys.org',
        ]) {
            expect(ANSWER_HOST.test(bad)).toBe(false);
        }
    });
});


describe('hostIsApp', () => {
    it('is the app’s own name under the enclave zones, nothing else', () => {
        expect(hostIsApp('drive-demo.apps.test.privasys.org', 'drive-demo')).toBe(true);
        expect(hostIsApp('drive.apps.privasys.org', 'drive')).toBe(true);
        expect(hostIsApp('globaml.apps.privasys.org', 'drive')).toBe(false);
        expect(hostIsApp('drive-demo.apps.privasys.org', 'drive')).toBe(false);
        expect(hostIsApp('drive.apps.privasys.org', undefined)).toBe(false);
        expect(hostIsApp('drive.test.privasys.org', 'drive')).toBe(false);
    });
});

describe('confirmFormSource', () => {
    const form = parseForm(GOOD)!;
    const APP = '11111111-2222-3333-4444-555555555555';
    const APP_HEX = '11111111222233334444555555555555';
    const HOST = 'drive.apps.test.privasys.org';
    const oids = (hex: string) => ({ custom_oids: [{ oid: '1.3.6.1.4.1.65230.4.1', value_hex: hex }], tee_type: 'tdx' });
    const confirmWith = (status: number, body: unknown) =>
        (makeRaTlsFetch as jest.Mock).mockReturnValue(async () => ({ ok: status === 200, status, json: async () => body }));

    beforeEach(() => {
        (inspectAttestation as jest.Mock).mockResolvedValue(oids(APP_HEX));
        (attestEnclave as jest.Mock).mockResolvedValue({ status: 'verified', mode: 'deterministic', challenged: false, result: {} });
        confirmWith(200, { open: true, form_id: form.id, form_digest: form.digest });
    });

    it('confirms when the app at its own host has this form open', async () => {
        await expect(confirmFormSource({ form, appId: APP, appSlug: 'drive', platformHost: HOST })).resolves.toMatchObject({ host: HOST });
    });

    it('refuses a host that is not the app’s own', async () => {
        await expect(confirmFormSource({ form, appId: APP, appSlug: 'globaml', platformHost: HOST })).rejects.toMatchObject({ reason: 'not-the-app' });
        expect(inspectAttestation).not.toHaveBeenCalledWith('evil.example');
    });

    it('refuses another app attested at that host', async () => {
        (inspectAttestation as jest.Mock).mockResolvedValue(oids('99999999222233334444555555555555'));
        await expect(confirmFormSource({ form, appId: APP, appSlug: 'drive', platformHost: HOST })).rejects.toMatchObject({ reason: 'not-the-app' });
    });

    it('refuses an attestation that does not verify', async () => {
        (attestEnclave as jest.Mock).mockResolvedValue({ status: 'failed', mode: 'deterministic', challenged: false });
        await expect(confirmFormSource({ form, appId: APP, appSlug: 'drive', platformHost: HOST })).rejects.toMatchObject({ reason: 'unverified' });
    });

    it.each([
        ['does not know it', 404, {}],
        ['has another digest', 200, { open: true, form_id: 'req_1', form_digest: 'ff'.repeat(32) }],
        ['says it is closed', 200, { open: false, form_id: 'req_1' }],
    ])('refuses when the app %s', async (_n, status, body) => {
        confirmWith(status as number, body);
        await expect(confirmFormSource({ form, appId: APP, appSlug: 'drive', platformHost: HOST })).rejects.toMatchObject({ reason: 'not-confirmed' });
    });

    // A refused form is removed for good when the app is not waiting on it,
    // so an app that is only restarting must not read as that.
    it.each([500, 502, 503, 408, 429])('takes a %i as unreachable, not as not waiting', async (status) => {
        confirmWith(status, {});
        await expect(confirmFormSource({ form, appId: APP, appSlug: 'drive', platformHost: HOST })).rejects.toMatchObject({ reason: 'unreachable' });
    });
});

describe('removedWhenRefused', () => {
    it.each(['not-confirmed', 'not-the-app'] as const)('removes a form refused as %s', (reason) => {
        expect(removedWhenRefused(reason)).toBe(true);
    });
    it.each(['unverified', 'unreachable'] as const)('keeps a form refused as %s, to try again', (reason) => {
        expect(removedWhenRefused(reason)).toBe(false);
    });
});
