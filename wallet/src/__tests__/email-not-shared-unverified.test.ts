// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * An address the holder merely typed is never handed to a relying party.
 *
 * Mail is how accounts are recovered and how people are reached, so an
 * unchecked address looks like a fact about the holder while being whatever
 * was typed, including somebody else's. Both resolvers refuse it: the one
 * behind sign-in disclosure and the consent screen's preview, and the one
 * behind a standalone data request.
 */

// Same two stand-ins as the other consent tests: the service pulls in
// expo-crypto for its record ids and react-native for storage, neither of
// which this environment provides. Nothing under test here needs either.
jest.mock('expo-crypto', () => ({
    getRandomBytesAsync: jest.fn(async (n: number) => new Uint8Array(n)),
    digestStringAsync: jest.fn(async () => '0'.repeat(64)),
    CryptoDigestAlgorithm: { SHA256: 'SHA-256' },
}));

jest.mock('@/utils/storage', () => {
    const store: Record<string, string> = {};
    return {
        getItemAsync: jest.fn(async (key: string) => store[key] ?? null),
        setItemAsync: jest.fn(async (key: string, value: string) => {
            store[key] = value;
        }),
        deleteItemAsync: jest.fn(async (key: string) => {
            delete store[key];
        }),
    };
});

import { isEmailVerified, selfAssertedValue, verifiedEmail } from '@/services/attributes';
import { getAttributeValues } from '@/services/consent';
import { useProfileStore, type ProfileAttribute, type UserProfile } from '@/stores/profile';

function emailAttr(value: string, verified: boolean): ProfileAttribute {
    return {
        key: 'email',
        label: 'Email',
        value,
        source: verified ? 'provider' : 'manual',
        verified,
        ...(verified
            ? {
                  verifications: [
                      {
                          verifier: 'privasys.id',
                          verifierDisplayName: 'Privasys',
                          method: 'email_code' as const,
                          assurance: 'provider' as const,
                          verifiedAt: 1,
                          evidence: 'receipt',
                      },
                  ],
              }
            : {}),
    };
}

function profileWith(mirror: string, attributes: ProfileAttribute[]): UserProfile {
    const profile: UserProfile = {
        displayName: 'Ada',
        email: mirror,
        avatarUri: '',
        locale: 'en-GB',
        did: 'did:key:z1',
        canonicalDid: 'did:web:privasys.id:users:1',
        pairwiseSeed: 'seed',
        linkedProviders: [],
        attributes,
        createdAt: 0,
        updatedAt: 0,
    };
    useProfileStore.setState({ profile });
    return profile;
}

describe('an unverified address is withheld', () => {
    it('is not resolved for disclosure, however the profile mirrors it', () => {
        const profile = profileWith('typed@example.com', [emailAttr('typed@example.com', false)]);
        expect(selfAssertedValue(profile, 'email')).toBeUndefined();
        expect(verifiedEmail(profile)).toBeUndefined();
        expect(isEmailVerified(profile, 'typed@example.com')).toBe(false);
        expect(getAttributeValues(['email'])['email']).toBeUndefined();
    });

    it('is withheld even when the mirror holds it and no attribute does', () => {
        const profile = profileWith('ghost@example.com', []);
        expect(selfAssertedValue(profile, 'email')).toBeUndefined();
        expect(getAttributeValues(['email'])['email']).toBeUndefined();
    });
});

describe('a verified address goes out', () => {
    it('is resolved by both paths, and case is not identity', () => {
        const profile = profileWith('ada@example.org', [emailAttr('ada@example.org', true)]);
        expect(selfAssertedValue(profile, 'email')).toBe('ada@example.org');
        expect(getAttributeValues(['email'])['email']).toBe('ada@example.org');
        expect(isEmailVerified(profile, 'ADA@Example.org')).toBe(true);
    });

    it('prefers the one the profile mirrors when several are verified', () => {
        const profile = profileWith('second@example.org', [
            emailAttr('first@example.org', true),
            emailAttr('second@example.org', true),
        ]);
        expect(verifiedEmail(profile)).toBe('second@example.org');
    });

    it('falls back to a verified address when the mirror is an unverified one', () => {
        const profile = profileWith('typed@example.com', [
            emailAttr('typed@example.com', false),
            emailAttr('proved@example.org', true),
        ]);
        expect(verifiedEmail(profile)).toBe('proved@example.org');
    });
});
