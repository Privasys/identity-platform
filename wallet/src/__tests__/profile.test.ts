// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Smoke tests for profile store — CRUD operations, provider linking,
 * attribute management, and the new pairwiseSeed/canonicalDid fields.
 */

// Mock expo-secure-store / storage
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

import { useProfileStore, type UserProfile, type LinkedProvider, type ProfileAttribute } from '@/stores/profile';

// Reset store between tests
beforeEach(() => {
    useProfileStore.setState({ profile: null });
});

const baseProfile = (): Omit<UserProfile, 'createdAt' | 'updatedAt'> => ({
    displayName: 'Test User',
    email: 'test@privasys.org',
    avatarUri: '',
    locale: 'en',
    did: 'did:key:zTestDevice',
    canonicalDid: 'did:web:privasys.id:users:abc123',
    pairwiseSeed: 'ab'.repeat(32),
    linkedProviders: [],
    attributes: [],
});

describe('profile store', () => {
    it('creates a profile with timestamps', () => {
        useProfileStore.getState().createProfile(baseProfile());
        const profile = useProfileStore.getState().profile;

        expect(profile).not.toBeNull();
        expect(profile!.displayName).toBe('Test User');
        expect(profile!.canonicalDid).toBe('did:web:privasys.id:users:abc123');
        expect(profile!.pairwiseSeed).toBe('ab'.repeat(32));
        expect(profile!.createdAt).toBeGreaterThan(0);
        expect(profile!.updatedAt).toBe(profile!.createdAt);
    });

    it('updates profile fields', () => {
        useProfileStore.getState().createProfile(baseProfile());
        useProfileStore.getState().updateProfile({ displayName: 'Updated Name' });

        const profile = useProfileStore.getState().profile;
        expect(profile!.displayName).toBe('Updated Name');
        expect(profile!.email).toBe('test@privasys.org'); // unchanged
    });

    it('updates canonicalDid and pairwiseSeed', () => {
        useProfileStore.getState().createProfile(baseProfile());
        useProfileStore.getState().updateProfile({
            canonicalDid: 'did:web:privasys.id:users:newid',
            pairwiseSeed: 'cd'.repeat(32),
        });

        const profile = useProfileStore.getState().profile;
        expect(profile!.canonicalDid).toBe('did:web:privasys.id:users:newid');
        expect(profile!.pairwiseSeed).toBe('cd'.repeat(32));
    });

    describe('linked providers', () => {
        it('links and unlinks a provider', () => {
            useProfileStore.getState().createProfile(baseProfile());

            const provider: LinkedProvider = {
                provider: 'github',
                displayName: 'GitHub',
                sub: 'gh-12345',
                email: 'test@github.com',
                linkedAt: Date.now() / 1000,
            };

            useProfileStore.getState().linkProvider(provider);
            expect(useProfileStore.getState().profile!.linkedProviders).toHaveLength(1);
            expect(useProfileStore.getState().profile!.linkedProviders[0].sub).toBe('gh-12345');

            useProfileStore.getState().unlinkProvider('github');
            expect(useProfileStore.getState().profile!.linkedProviders).toHaveLength(0);
        });

        it('replaces a provider if re-linked', () => {
            useProfileStore.getState().createProfile(baseProfile());

            const v1: LinkedProvider = { provider: 'google', displayName: 'Google', sub: 'g-1', linkedAt: 1 };
            const v2: LinkedProvider = { provider: 'google', displayName: 'Google', sub: 'g-2', linkedAt: 2 };

            useProfileStore.getState().linkProvider(v1);
            useProfileStore.getState().linkProvider(v2);

            const providers = useProfileStore.getState().profile!.linkedProviders;
            expect(providers).toHaveLength(1);
            expect(providers[0].sub).toBe('g-2');
        });
    });

    describe('attributes', () => {
        it('sets and removes attributes', () => {
            useProfileStore.getState().createProfile(baseProfile());

            const attr: ProfileAttribute = {
                key: 'phone',
                label: 'Phone',
                value: '+1234567890',
                source: 'manual',
                verified: false,
            };

            useProfileStore.getState().setAttribute(attr);
            expect(useProfileStore.getState().profile!.attributes).toHaveLength(1);
            expect(useProfileStore.getState().profile!.attributes[0].value).toBe('+1234567890');

            useProfileStore.getState().removeAttribute('phone');
            expect(useProfileStore.getState().profile!.attributes).toHaveLength(0);
        });

        it('getAttributes returns matching attributes', () => {
            useProfileStore.getState().createProfile(baseProfile());
            useProfileStore.getState().setAttribute({
                key: 'company', label: 'Company', value: 'Privasys', source: 'manual', verified: false,
            });
            useProfileStore.getState().setAttribute({
                key: 'title', label: 'Title', value: 'Engineer', source: 'manual', verified: false,
            });

            const result = useProfileStore.getState().getAttributes(['company', 'missing']);
            expect(result).toHaveLength(1);
            expect(result[0].key).toBe('company');
        });
    });

    it('clearProfile removes everything', () => {
        useProfileStore.getState().createProfile(baseProfile());
        expect(useProfileStore.getState().profile).not.toBeNull();

        useProfileStore.getState().clearProfile();
        expect(useProfileStore.getState().profile).toBeNull();
    });
});
