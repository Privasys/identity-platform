// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Sealed notifications, one key per identity.
 *
 * A notification to a service identity must open on the phone that holds it,
 * with a key no other identity shares, and the push must not say which key it
 * was sealed to.
 */

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
jest.mock('@/services/sovereign', () => ({ ensureDataRoot: jest.fn() }));
jest.mock('expo-crypto', () => ({ getRandomBytes: (n: number) => new Uint8Array(n) }));

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { IDP_HOST } from '@/services/identities';
import { identitySealPub, openSealedNotification } from '@/services/notify-seal';
import { useAuthStore } from '@/stores/auth';
import { useProfileStore } from '@/stores/profile';
import { base64urlToBytes, bytesToBase64url } from '@/utils/encoding';

const SEED = 'ab'.repeat(32);
const DRIVE_ID = 'D'.repeat(43);
const AI_ID = 'A'.repeat(43);

/** The IdP's sealToWallet, in TypeScript. */
function seal(pubB64: string, type: string, payload: object): string {
    const eph = x25519.utils.randomSecretKey();
    const shared = x25519.getSharedSecret(eph, base64urlToBytes(pubB64));
    const key = hkdf(sha256, shared, undefined, new TextEncoder().encode('privasys-notify-v1'), 32);
    const nonce = new Uint8Array(24).fill(1);
    const ct = xchacha20poly1305(key, nonce, new TextEncoder().encode(type)).encrypt(
        new TextEncoder().encode(JSON.stringify(payload)),
    );
    const out = new Uint8Array(32 + 24 + ct.length);
    out.set(x25519.getPublicKey(eph), 0);
    out.set(nonce, 32);
    out.set(ct, 56);
    return bytesToBase64url(out);
}

function holdIdentity(id: string) {
    useAuthStore.setState((s) => ({
        credentials: [
            ...s.credentials,
            {
                credentialId: `c-${id[0]}`,
                rpId: 'privasys.id',
                origin: IDP_HOST,
                keyAlias: 'k',
                userHandle: bytesToBase64url(new TextEncoder().encode(id)),
                userName: 'x',
                registeredAt: 1,
            },
        ],
    }));
}

beforeEach(() => {
    useAuthStore.setState({ credentials: [] });
    useProfileStore.setState({ profile: { pairwiseSeed: SEED } as any });
});

it('gives each identity its own key', () => {
    const drive = identitySealPub(DRIVE_ID);
    expect(drive).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(identitySealPub(AI_ID)).not.toBe(drive);
    expect(identitySealPub(DRIVE_ID)).toBe(drive);
});

it('registers no key without a seed or an id, which keeps what the IdP has', () => {
    expect(identitySealPub(undefined)).toBe('');
    useProfileStore.setState({ profile: null as any });
    expect(identitySealPub(DRIVE_ID)).toBe('');
});

it('opens a notification sealed to an identity this phone holds', async () => {
    holdIdentity(AI_ID);
    holdIdentity(DRIVE_ID);
    const sealed = seal(identitySealPub(DRIVE_ID), 'share-request', { node_name: 'Report.pdf' });
    await expect(openSealedNotification(sealed, 'share-request')).resolves.toEqual({ node_name: 'Report.pdf' });
});

it('does not open one sealed to an identity this phone does not hold', async () => {
    holdIdentity(AI_ID);
    const sealed = seal(identitySealPub(DRIVE_ID), 'share-request', { node_name: 'Report.pdf' });
    await expect(openSealedNotification(sealed, 'share-request')).resolves.toBeNull();
});

it('binds the notification type, so a payload cannot be replayed as another kind', async () => {
    holdIdentity(DRIVE_ID);
    const sealed = seal(identitySealPub(DRIVE_ID), 'share-request', { node_name: 'Report.pdf' });
    await expect(openSealedNotification(sealed, 'share-decision')).resolves.toBeNull();
});
