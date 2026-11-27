// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * This phone proving its push token is its own.
 */

import { ed25519 } from '@noble/curves/ed25519.js';

import { base64urlToBytes, bytesToBase64url } from '../utils/encoding';

const mockSecret = bytesToBase64url(new Uint8Array(32).fill(7));
jest.mock('../services/devices', () => ({
    ensureDevice: jest.fn(async () => ({ id: 'device', secret: mockSecret })),
}));

import { answerBindChallenge, dismissProof, registrationProof, repeatWhenBound, clearPushBindLocalState } from '../services/push-bind';

const utf8 = (s: string) => new TextEncoder().encode(s);
const verifies = (sig: string, text: string, pub: string) =>
    ed25519.verify(base64urlToBytes(sig), utf8(text), base64urlToBytes(pub));

let fetched: { url: string; body: Record<string, unknown> }[] = [];
let answerOk = true;

beforeEach(() => {
    clearPushBindLocalState();
    fetched = [];
    answerOk = true;
    (global as any).fetch = jest.fn(async (url: string, init: { body: string }) => {
        fetched.push({ url, body: JSON.parse(init.body) });
        return { ok: answerOk, status: answerOk ? 200 : 403 };
    });
});

describe('a registration', () => {
    it('is signed over the token, the subject and the time', async () => {
        const p = await registrationProof('tok', 'alice');
        expect(p.issued_at).toBeGreaterThan(0);
        expect(verifies(p.bind_sig!, `privasys-push-register/v1\ntok\nalice\n${p.issued_at}`, p.bind_pub)).toBe(true);
        // Not good for another subject or another token.
        expect(verifies(p.bind_sig!, `privasys-push-register/v1\ntok\nmallory\n${p.issued_at}`, p.bind_pub)).toBe(false);
        expect(verifies(p.bind_sig!, `privasys-push-register/v1\nother\nalice\n${p.issued_at}`, p.bind_pub)).toBe(false);
    });

    it('names the key alone when the subject is not known', async () => {
        const p = await registrationProof('tok');
        expect(p.bind_pub).toBe((await registrationProof('tok', 'alice')).bind_pub);
        expect(p.bind_sig).toBeUndefined();
    });
});

describe('a challenge', () => {
    it('opened for this phone is answered, signed, and the waiting registrations are made again', async () => {
        const { bind_pub } = await registrationProof('tok');
        const again = jest.fn(async () => undefined);
        repeatWhenBound('alice', again);
        repeatWhenBound('alice-2', again);

        expect(await answerBindChallenge({ type: 'push-bind', nonce: 'n-1', bind_pub }, 'tok')).toBe(true);
        expect(fetched).toHaveLength(1);
        expect(fetched[0].url).toMatch(/\/push-token\/bind$/);
        const b = fetched[0].body as { push_token: string; bind_pub: string; nonce: string; sig: string };
        expect(b).toMatchObject({ push_token: 'tok', bind_pub, nonce: 'n-1' });
        expect(verifies(b.sig, 'privasys-push-bind/v1\ntok\nn-1', bind_pub)).toBe(true);
        expect(again).toHaveBeenCalledTimes(2);

        // Each waits once: a second challenge repeats nothing.
        await answerBindChallenge({ type: 'push-bind', nonce: 'n-2', bind_pub }, 'tok');
        expect(again).toHaveBeenCalledTimes(2);
    });

    it("opened for another key is someone else's registration of this token: not answered", async () => {
        const stranger = bytesToBase64url(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
        const again = jest.fn(async () => undefined);
        repeatWhenBound('alice', again);
        expect(await answerBindChallenge({ type: 'push-bind', nonce: 'n-1', bind_pub: stranger }, 'tok')).toBe(false);
        expect(fetched).toHaveLength(0);
        expect(again).not.toHaveBeenCalled();
    });

    it('with no nonce, no key or no token is not answered', async () => {
        const { bind_pub } = await registrationProof('tok');
        expect(await answerBindChallenge({ type: 'push-bind', bind_pub }, 'tok')).toBe(false);
        expect(await answerBindChallenge({ type: 'push-bind', nonce: 'n' }, 'tok')).toBe(false);
        expect(await answerBindChallenge({ type: 'push-bind', nonce: 'n', bind_pub }, null)).toBe(false);
        expect(await answerBindChallenge(null, 'tok')).toBe(false);
        expect(fetched).toHaveLength(0);
    });

    it('that privasys.id refuses repeats nothing, and the registrations keep waiting', async () => {
        const { bind_pub } = await registrationProof('tok');
        const again = jest.fn(async () => undefined);
        repeatWhenBound('alice', again);
        answerOk = false;
        expect(await answerBindChallenge({ type: 'push-bind', nonce: 'n-1', bind_pub }, 'tok')).toBe(false);
        expect(again).not.toHaveBeenCalled();
        answerOk = true;
        expect(await answerBindChallenge({ type: 'push-bind', nonce: 'n-2', bind_pub }, 'tok')).toBe(true);
        expect(again).toHaveBeenCalledTimes(1);
    });
});

describe('clearing a notification on the other phones', () => {
    it('is signed over the token, the notification key and the time', async () => {
        const { bind_pub } = await registrationProof('tok');
        const p = await dismissProof('tok', 'AbCdEfGhIjKlMnOpQrStUv');
        expect(verifies(p.sig, `privasys-push-dismiss/v1\ntok\nAbCdEfGhIjKlMnOpQrStUv\n${p.issued_at}`, bind_pub)).toBe(true);
    });
});

describe('a challenge carried by a notification', () => {
    it('is answered from its bind_nonce, beside whatever the notification is about, and once', async () => {
        const { bind_pub } = await registrationProof('tok');
        const data = { type: 'vault-approval', vault_op: 'op-1', bind_nonce: 'n-visible', bind_pub };
        expect(await answerBindChallenge(data, 'tok')).toBe(true);
        const b = fetched[0].body as { nonce: string; sig: string };
        expect(b.nonce).toBe('n-visible');
        expect(verifies(b.sig, 'privasys-push-bind/v1\ntok\nn-visible', bind_pub)).toBe(true);
        // Shown, then opened, then found in the tray: the same nonce is not sent again.
        expect(await answerBindChallenge(data, 'tok')).toBe(false);
        expect(fetched).toHaveLength(1);
    });

    it("is ignored when it names another key, as someone else's registration of this token would", async () => {
        const stranger = bytesToBase64url(ed25519.getPublicKey(new Uint8Array(32).fill(9)));
        expect(await answerBindChallenge({ type: 'auth-request', bind_nonce: 'n', bind_pub: stranger }, 'tok')).toBe(false);
        expect(fetched).toHaveLength(0);
    });
});
