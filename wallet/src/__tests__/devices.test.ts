// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Several phones of one holder.
 *
 * A phone's tags on two identities must not relate them; the registry must
 * merge so that a revocation is never undone by a stale copy; the transfer must
 * open only on the phone it was sealed to, with the same six digits on both;
 * the recovery key must change with the epoch, so a revoked phone's seed stops
 * working. The signed messages are the contract with the IdP, which checks the
 * same bytes in internal/recovery/devices_test.go.
 */

jest.mock('expo-crypto', () => ({
    getRandomBytes: (n: number) => new Uint8Array(require('crypto').randomBytes(n)),
}));
jest.mock('@/utils/storage', () => {
    const mockStore: Record<string, string> = {};
    return {
        getItemAsync: jest.fn(async (k: string) => mockStore[k] ?? null),
        setItemAsync: jest.fn(async (k: string, v: string) => {
            mockStore[k] = v;
        }),
        deleteItemAsync: jest.fn(async (k: string) => {
            delete mockStore[k];
        }),
    };
});
jest.mock('@/services/kyc', () => ({ loadKycRecords: async () => [], saveKycRecord: async () => undefined }));
jest.mock('expo-device', () => ({ modelName: 'Test Phone' }));
jest.mock('@/services/sovereign', () => ({
    ensureDataRoot: jest.fn(async () => new Uint8Array(32).fill(9)),
    peekDataRoot: jest.fn(async () => new Uint8Array(32).fill(9)),
}));

import { ed25519 } from '@noble/curves/ed25519.js';

import { openMessage, sealMessage } from '@/services/device-sync';
import {
    deviceTagFor,
    emptyRegistry,
    enrolMessage,
    mergeRegistries,
    openRegistry,
    openTransfer,
    pairingCode,
    pairingKeys,
    pairingLink,
    parsePairingLink,
    relayAddressFor,
    revokeMessage,
    sealRegistry,
    sealTransfer,
    type Registry,
} from '@/services/devices';
import { deriveRecoveryKey, sealIndex } from '@/services/identities';
import { bytesToBase64url } from '@/utils/encoding';

const SECRET_A = bytesToBase64url(new Uint8Array(32).fill(1));
const SECRET_B = bytesToBase64url(new Uint8Array(32).fill(2));
const SEED = '00'.repeat(31) + '01';
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

describe('device tags', () => {
    it('are stable for one phone and identity, and unrelated across identities and phones', () => {
        expect(deviceTagFor(SECRET_A, 'id-1')).toBe(deviceTagFor(SECRET_A, 'id-1'));
        expect(deviceTagFor(SECRET_A, 'id-1')).not.toBe(deviceTagFor(SECRET_A, 'id-2'));
        expect(deviceTagFor(SECRET_A, 'id-1')).not.toBe(deviceTagFor(SECRET_B, 'id-1'));
        // The shape the IdP accepts: base64url, 22 characters.
        expect(deviceTagFor(SECRET_A, 'id-1')).toMatch(/^[A-Za-z0-9_-]{22}$/);
    });

    it('relay addresses are per phone and not a tag', () => {
        expect(relayAddressFor(SECRET_A)).not.toBe(relayAddressFor(SECRET_B));
        expect(relayAddressFor(SECRET_A)).toMatch(/^[A-Za-z0-9_-]{22}$/);
    });
});

describe('registry', () => {
    const key = new Uint8Array(32).fill(4);
    const reg = (over: Partial<Registry>): Registry => ({ ...emptyRegistry(), ...over });
    const phone = (id: string, secret = SECRET_A) => ({ id, name: id, createdAt: 1, secret });

    it('round-trips, and does not open under another key', () => {
        const r = reg({
            identities: [{ rpId: 'drive.example', userHandle: 'h1', epoch: 2 }],
            devices: [phone('a')],
            epochs: [{ n: 2, secret: SECRET_B }],
        });
        const blob = sealRegistry(key, r);
        expect(openRegistry(key, blob)).toEqual(r);
        expect(openRegistry(new Uint8Array(32).fill(5), blob)).toBeNull();
    });

    it('reads the identity index it replaces, as identities on epoch 0', () => {
        const blob = sealIndex(key, [{ rpId: 'drive.example', userHandle: 'old' }]);
        expect(openRegistry(key, blob)?.identities).toEqual([{ rpId: 'drive.example', userHandle: 'old', epoch: 0 }]);
    });

    it('a revocation wins over a stale copy that still lists the phone', () => {
        const stale = reg({ devices: [phone('a'), phone('b', SECRET_B)] });
        const fresh = reg({ devices: [phone('a')], revoked: ['b'] });
        expect(mergeRegistries(stale, fresh).devices.map((d) => d.id)).toEqual(['a']);
        expect(mergeRegistries(fresh, stale).devices.map((d) => d.id)).toEqual(['a']);
    });

    it('keeps the newest epoch of each identity and every epoch secret', () => {
        const a = reg({ identities: [{ rpId: 'x', userHandle: 'h', epoch: 1 }], epochs: [{ n: 1, secret: SECRET_A }] });
        const b = reg({ identities: [{ rpId: 'x', userHandle: 'h', epoch: 3 }], epochs: [{ n: 3, secret: SECRET_B }] });
        const m = mergeRegistries(a, b);
        expect(m.identities).toEqual([{ rpId: 'x', userHandle: 'h', epoch: 3 }]);
        expect(m.epochs.map((e) => e.n)).toEqual([1, 3]);
        expect(mergeRegistries(b, a).identities[0].epoch).toBe(3);
    });
});

describe('pairing', () => {
    it('opens only with the new phone’s key, and both phones show the same code', () => {
        const receiver = pairingKeys();
        const receiverPub = bytesToBase64url(receiver.publicKey);
        const { senderPub, blob } = sealTransfer(receiverPub, { v: 1, seed: SEED });
        expect(openTransfer<{ seed: string }>(receiver.secretKey, senderPub, blob).seed).toBe(SEED);
        expect(() => openTransfer(pairingKeys().secretKey, senderPub, blob)).toThrow();
        expect(pairingCode(receiverPub, senderPub)).toMatch(/^\d{3} \d{3}$/);
        expect(pairingCode(receiverPub, senderPub)).toBe(pairingCode(receiverPub, senderPub));
        expect(pairingCode(receiverPub, senderPub)).not.toBe(pairingCode(receiverPub, bytesToBase64url(pairingKeys().publicKey)));
    });

    it('a pairing link parses back, and nothing else does', () => {
        const pub = bytesToBase64url(pairingKeys().publicKey);
        const slot = 'slot-slot-slot-slot-slot-slot-12';
        expect(parsePairingLink(pairingLink(slot, pub))).toEqual({ slot, key: pub });
        expect(parsePairingLink('privasys-wallet://account-recovery?guardian=x')).toBeNull();
        expect(parsePairingLink('privasys-wallet://pair?s=short&k=' + pub)).toBeNull();
    });
});

describe('recovery epochs', () => {
    it('epoch 0 is the key from before devices; a new epoch gives a key the seed alone cannot', () => {
        const v1 = deriveRecoveryKey(SEED, 'h').publicKey;
        expect(deriveRecoveryKey(SEED, 'h', null).publicKey).toEqual(v1);
        const e1 = deriveRecoveryKey(SEED, 'h', { n: 1, secret: SECRET_A }).publicKey;
        const e2 = deriveRecoveryKey(SEED, 'h', { n: 2, secret: SECRET_A }).publicKey;
        const e1b = deriveRecoveryKey(SEED, 'h', { n: 1, secret: SECRET_B }).publicKey;
        expect(hex(e1)).not.toBe(hex(v1));
        expect(hex(e1)).not.toBe(hex(e2));
        expect(hex(e1)).not.toBe(hex(e1b));
    });
});

describe('signed messages (the IdP checks the same bytes)', () => {
    const challenge = new Uint8Array([1, 2, 3, 4]);

    it('enrol is domain ‖ 0 ‖ user ‖ 0 ‖ challenge', () => {
        expect(hex(enrolMessage('user-1', challenge))).toBe(
            Buffer.concat([Buffer.from('privasys-identity-enrol/v1\0user-1\0'), Buffer.from(challenge)]).toString('hex'),
        );
    });

    it('revoke adds ‖ 0 ‖ tag ‖ 0 ‖ new key, and binds both', () => {
        const msg = revokeMessage('user-1', challenge, 'tag', 'newpub');
        expect(hex(msg)).toBe(
            Buffer.concat([
                Buffer.from('privasys-identity-revoke/v1\0user-1\0'),
                Buffer.from(challenge),
                Buffer.from('\0tag\0newpub'),
            ]).toString('hex'),
        );
        const { secretKey, publicKey } = deriveRecoveryKey(SEED, 'user-1');
        const sig = ed25519.sign(msg, secretKey);
        expect(ed25519.verify(sig, revokeMessage('user-1', challenge, 'other-tag', 'newpub'), publicKey)).toBe(false);
        expect(ed25519.verify(sig, revokeMessage('user-1', challenge, 'tag', 'attacker'), publicKey)).toBe(false);
    });
});

describe('relay messages', () => {
    it('open only under the same data root', () => {
        const root = new Uint8Array(32).fill(9);
        const blob = sealMessage(root, { kind: 'ack', id: 'm1', from: 'a' });
        expect(openMessage(root, blob)).toEqual({ kind: 'ack', id: 'm1', from: 'a' });
        expect(openMessage(new Uint8Array(32).fill(8), blob)).toBeNull();
    });
});
