// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What the wallet records about a disclosure.
 *
 * Until now it kept the attribute NAMES, so "what did this app actually get"
 * had no answer: a holder who has since changed their email cannot read it off
 * their profile, because the profile holds what is true now and the question is
 * about what left the device then.
 */

// The consent service pulls in expo-crypto for its record ids, which this
// environment cannot load. Nothing under test here needs it.
jest.mock('expo-crypto', () => ({
    getRandomBytesAsync: jest.fn(async (n: number) => new Uint8Array(n)),
    digestStringAsync: jest.fn(async () => '0'.repeat(64)),
    CryptoDigestAlgorithm: { SHA256: 'SHA-256' },
}));

// Storage is in-memory here, as in the other store tests: the module pulls
// in react-native, which this environment does not provide.
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

import { snapshotDisclosed } from '@/services/consent';
import { useProfileStore } from '@/stores/profile';

function profileWith(email: string, extra: { key: string; value: string }[] = []) {
    useProfileStore.setState({
        profile: {
            displayName: 'Ada',
            email,
            avatarUri: '',
            locale: 'en-GB',
            did: 'did:key:z1',
            canonicalDid: 'did:web:privasys.id:users:1',
            pairwiseSeed: 'seed',
            linkedProviders: [],
            attributes: extra.map((a) => ({
                key: a.key,
                label: a.key,
                value: a.value,
                source: 'manual' as const,
                verified: false,
            })),
            createdAt: 0,
            updatedAt: 0,
        },
    });
}

describe('snapshotDisclosed', () => {
    it('captures the value that is going out', () => {
        profileWith('ada@example.org');
        expect(snapshotDisclosed(['email'])).toEqual([{ key: 'email', value: 'ada@example.org' }]);
    });

    // The point of capturing at disclosure time rather than reading back later.
    it('is not affected by a later change to the profile', () => {
        profileWith('old@example.org');
        const then = snapshotDisclosed(['email']);
        profileWith('new@example.org');
        expect(then).toEqual([{ key: 'email', value: 'old@example.org' }]);
        expect(snapshotDisclosed(['email'])).toEqual([{ key: 'email', value: 'new@example.org' }]);
    });

    // A derived attribute is computed by the enclave from the identity receipt.
    // The wallet never holds a value for it, so what went was a proof, and
    // writing a value here would claim the service received something it did
    // not. `document_valid` and `age_band` are the two.
    it('records a derived attribute as a proof, with no value', () => {
        profileWith('ada@example.org');
        expect(snapshotDisclosed(['document_valid'])).toEqual([
            { key: 'document_valid', proofOnly: true },
        ]);
    });

    // Different from the above, and deliberately so: "a proof went" and "we do
    // not know what went" are not the same statement to put in front of
    // someone auditing their own disclosures.
    it('records neither value nor proof when the profile had nothing', () => {
        profileWith('ada@example.org');
        expect(snapshotDisclosed(['phone_number'])).toEqual([{ key: 'phone_number' }]);
    });

    it('keeps the order the attributes were approved in', () => {
        profileWith('ada@example.org', [{ key: 'name', value: 'Ada Lovelace' }]);
        expect(snapshotDisclosed(['name', 'email']).map((d) => d.key)).toEqual(['name', 'email']);
    });
});
