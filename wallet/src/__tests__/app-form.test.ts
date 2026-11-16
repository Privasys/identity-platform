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
jest.mock('../services/attestation', () => ({ inspectAttestation: jest.fn() }));
jest.mock('../services/fido2', () => ({ signVaultAssertion: jest.fn(async () => ({ id: 'c' })) }));
jest.mock('../services/attribute-approval-api', () => ({
    resolveStepUpCredential: jest.fn(() => ({ keyAlias: 'k', credentialId: 'c', serverRpId: 'privasys.id' })),
}));
jest.mock('../../modules/native-ratls/src/index', () => ({ makeRaTlsFetch: jest.fn() }));

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { formDigest, parseForm } from '../services/app-form';
import { answerForm, AnswerError } from '../services/app-form-answer';
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
        await expect(answerForm({ messageId: 'm1', form, appId: APP, action: 'approve' })).rejects.toMatchObject({ reason: 'mismatch' });
        expect(signVaultAssertion).not.toHaveBeenCalled();
    });

    it('never offers an action the form does not have', async () => {
        await expect(answerForm({ messageId: 'm1', form, appId: APP, action: 'wipe' })).rejects.toBeInstanceOf(AnswerError);
    });
});
