// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One import path for the Import screen and for linking a provider during a
 * sign-in: the same merge, the only difference what happens to a conflict.
 */

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

import { applyProviderImport, resolveImportConflict } from '@/services/provider-import';
import { useProfileStore, type LinkedProvider, type ProfileAttribute } from '@/stores/profile';

const GOOGLE: LinkedProvider = { provider: 'google', displayName: 'Google', sub: 'g1', linkedAt: 1 };

const attr = (key: string, value: string, extra: Partial<ProfileAttribute> = {}): ProfileAttribute => ({
    key,
    label: key,
    value,
    source: 'provider',
    sourceProvider: 'google',
    acquiredAt: 1,
    updatedAt: 1,
    ...extra,
});

const proof = { verifier: 'google', verifierDisplayName: 'Google', method: 'oidc_claim' as const, assurance: 'provider' as const, verifiedAt: 2, proof: 'jws' };

function holder(attributes: ProfileAttribute[], avatarUri = ''): void {
    useProfileStore.setState({ profile: null });
    useProfileStore.getState().createProfile({
        avatarUri,
        locale: 'en',
        did: 'did:key:z1',
        canonicalDid: 'did:web:privasys.id:users:1',
        pairwiseSeed: 'ab'.repeat(32),
        linkedProviders: [],
        attributes,
    });
}

const values = (key: string) => useProfileStore.getState().profile!.attributes.filter((a) => a.key === key).map((a) => a.value);

describe('applyProviderImport', () => {
    it('links the provider, adds what is missing and a second email beside the first', () => {
        holder([attr('email', 'me@example.org', { source: 'manual' })]);
        const out = applyProviderImport(GOOGLE, [attr('email', 'g@gmail.example'), attr('given_name', 'Ada')], { conflicts: 'ask' });
        expect(out).toEqual({ added: 2, strengthened: 0, conflicts: [], kept: 0 });
        expect(values('email')).toEqual(['me@example.org', 'g@gmail.example']);
        expect(values('given_name')).toEqual(['Ada']);
        expect(useProfileStore.getState().profile!.linkedProviders.map((p) => p.provider)).toEqual(['google']);
    });

    it('strengthens the same value with the proof it brings', () => {
        holder([attr('email', 'ada@example.org', { source: 'manual' })]);
        const out = applyProviderImport(GOOGLE, [attr('email', 'Ada@Example.org', { verifications: [proof] })], { conflicts: 'keep' });
        expect(out.strengthened).toBe(1);
        const held = useProfileStore.getState().profile!.attributes.find((a) => a.key === 'email')!;
        expect(held.verifications?.some((v) => v.proof === 'jws')).toBe(true);
    });

    it('asks about a differing value on the Import screen, and keeps the holder\'s during a sign-in', () => {
        holder([attr('given_name', 'Ada', { source: 'manual' })]);
        const asked = applyProviderImport(GOOGLE, [attr('given_name', 'Augusta')], { conflicts: 'ask' });
        expect(asked.conflicts).toHaveLength(1);
        expect(values('given_name')).toEqual(['Ada']);

        holder([attr('given_name', 'Ada', { source: 'manual' })]);
        const kept = applyProviderImport(GOOGLE, [attr('given_name', 'Augusta')], { conflicts: 'keep' });
        expect(kept).toEqual({ added: 0, strengthened: 0, conflicts: [], kept: 1 });
        expect(values('given_name')).toEqual(['Ada']);
    });

    it('imports only the selected keys', () => {
        holder([]);
        applyProviderImport(GOOGLE, [attr('given_name', 'Ada'), attr('family_name', 'Lovelace')], {
            selected: new Set(['family_name']),
            conflicts: 'ask',
        });
        expect(values('given_name')).toEqual([]);
        expect(values('family_name')).toEqual(['Lovelace']);
    });

    it('makes a first picture the avatar, and a chosen replacement too', () => {
        holder([]);
        applyProviderImport(GOOGLE, [attr('picture', 'https://example.org/a.png')], { conflicts: 'ask' });
        expect(useProfileStore.getState().profile!.avatarUri).toBe('https://example.org/a.png');

        const { conflicts } = applyProviderImport(GOOGLE, [attr('picture', 'https://example.org/b.png')], { conflicts: 'ask' });
        resolveImportConflict(conflicts[0], 'replace');
        expect(useProfileStore.getState().profile!.avatarUri).toBe('https://example.org/b.png');
    });
});
