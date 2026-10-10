// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Identities that survive losing the phone.
 *
 * A recovered seed must name every identity again, each identity must be
 * provable on its own, and nothing the IdP sees may relate one identity to
 * another. The fixed vector at the end is the contract with the IdP, which
 * checks the same bytes in internal/recovery/identity_test.go.
 */

jest.mock('expo-crypto', () => ({
    getRandomBytes: (n: number) => new Uint8Array(n).map((_, i) => (i * 7 + 3) & 0xff),
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
jest.mock('@/services/sovereign', () => ({ ensureDataRoot: jest.fn(async () => new Uint8Array(32).fill(9)) }));

import { ed25519 } from '@noble/curves/ed25519.js';

import {
    canonicalHandle,
    deriveIdentityHandle,
    deriveRecoveryKey,
    IDP_HOST,
    legacyFromCredentials,
    openIndex,
    recoveryMessage,
    sealIndex,
    serverIdOf,
} from '@/services/identities';
import type { Credential } from '@/stores/auth';
import { bytesToBase64url } from '@/utils/encoding';

const SEED = '00'.repeat(31) + '01';
const OTHER_SEED = '00'.repeat(31) + '02';
const b64text = (s: string) => bytesToBase64url(new TextEncoder().encode(s));

function cred(rpId: string, serverId: string, extra: Partial<Credential> = {}): Credential {
    return {
        credentialId: `cred-${serverId.slice(0, 6)}`,
        rpId,
        origin: IDP_HOST,
        keyAlias: 'k',
        // What the IdP echoes back as user.id: the handle, encoded once more.
        userHandle: b64text(serverId),
        userName: 'x',
        registeredAt: 1,
        ...extra,
    };
}

describe('derived identities', () => {
    it('are the same for the same seed and service, so a recovered seed finds them again', () => {
        expect(deriveIdentityHandle(SEED, 'privasys.id')).toBe(deriveIdentityHandle(SEED, 'privasys.id'));
        expect(deriveIdentityHandle(SEED, 'privasys.id')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    });

    it('differ per service and per holder', () => {
        const drive = deriveIdentityHandle(SEED, 'privasys.id');
        expect(deriveIdentityHandle(SEED, 'exchange.example')).not.toBe(drive);
        expect(deriveIdentityHandle(OTHER_SEED, 'privasys.id')).not.toBe(drive);
    });

    it('never coincide with the main account, which the phrase recovers', () => {
        expect(deriveIdentityHandle(SEED, 'privasys.id')).not.toBe(canonicalHandle(SEED));
    });
});

describe('recovery keys', () => {
    it('sign the exact message the IdP checks, and only for that identity', () => {
        const id = deriveIdentityHandle(SEED, 'privasys.id');
        const { secretKey, publicKey } = deriveRecoveryKey(SEED, id);
        const challenge = new Uint8Array(32).fill(7);
        const sig = ed25519.sign(recoveryMessage(id, challenge), secretKey);
        expect(ed25519.verify(sig, recoveryMessage(id, challenge), publicKey)).toBe(true);
        expect(ed25519.verify(sig, recoveryMessage('another-identity', challenge), publicKey)).toBe(false);
    });

    it('are unrelated across identities, so two keys reveal nothing about each other', () => {
        const a = deriveRecoveryKey(SEED, deriveIdentityHandle(SEED, 'privasys.id')).publicKey;
        const b = deriveRecoveryKey(SEED, deriveIdentityHandle(SEED, 'exchange.example')).publicKey;
        expect(bytesToBase64url(a)).not.toBe(bytesToBase64url(b));
    });
});

describe('older identities', () => {
    it('reads the IdP user id back from the stored, re-encoded handle', () => {
        const random = 'q'.repeat(43);
        expect(serverIdOf(cred('privasys.id', random))).toBe(random);
        // A value that is not double-encoded text is already the id.
        expect(serverIdOf({ userHandle: bytesToBase64url(new Uint8Array(32).fill(250)) })).toBe(
            bytesToBase64url(new Uint8Array(32).fill(250)),
        );
    });

    it('lists random identities, active one first, and leaves out derived ones and the main account', () => {
        const old = 'A'.repeat(43);
        const older = 'B'.repeat(43);
        const derived = deriveIdentityHandle(SEED, 'privasys.id');
        const creds = [
            cred('privasys.id', older, { credentialId: 'older', registeredAt: 5 }),
            cred('privasys.id', old, { credentialId: 'old', registeredAt: 1 }),
            cred('privasys.id', derived, { credentialId: 'derived' }),
            cred('privasys.id', canonicalHandle(SEED), { credentialId: 'main' }),
            cred('enclave.example', 'C'.repeat(43), { origin: 'enclave.example' }),
        ];
        expect(legacyFromCredentials(creds, SEED, 'old')).toEqual([
            { rpId: 'privasys.id', userHandle: old },
            { rpId: 'privasys.id', userHandle: older },
        ]);
    });

    it('keeps their list sealed under the data root key', () => {
        const key = new Uint8Array(32).fill(4);
        const entries = [{ rpId: 'privasys.id', userHandle: 'A'.repeat(43) }];
        const blob = sealIndex(key, entries);
        expect(blob).not.toContain('privasys.id');
        expect(openIndex(key, blob)).toEqual(entries);
        expect(openIndex(new Uint8Array(32).fill(5), blob)).toBeNull();
    });
});

describe('the contract with the IdP', () => {
    it('produces the fixed vector the IdP verifies', () => {
        const id = deriveIdentityHandle(SEED, 'privasys.id');
        const { secretKey, publicKey } = deriveRecoveryKey(SEED, id);
        const challenge = new Uint8Array(32).map((_, i) => i);
        const sig = ed25519.sign(recoveryMessage(id, challenge), secretKey);
        // If any of these change, update TestTheWalletVectorVerifies in the IdP.
        expect({
            id,
            publicKey: bytesToBase64url(publicKey),
            signature: bytesToBase64url(sig),
        }).toMatchSnapshot();
    });
});
