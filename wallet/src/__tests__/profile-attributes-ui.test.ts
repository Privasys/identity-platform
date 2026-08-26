// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Two rules the Personal Data and Profile screens depend on.
 *
 * 1. Nobody may type a government-verified attribute. A passport number, a
 *    document expiry or an "18 or older" proof means something only because a
 *    chip signed for it. The Personal Data screen was offering all fifteen of
 *    them as "Add:" chips beside the ordinary ones, on a screen whose whole
 *    subject is provenance (2026-08-26).
 *
 * 2. A wallet that knows its owner's name must use it. `displayName` is seeded
 *    with a placeholder at setup and only an explicit Display Name overwrites
 *    it, so a profile carrying an imported first and last name still introduced
 *    its owner as "Privasys User".
 */

jest.mock('@/utils/storage', () => ({
    getItemAsync: jest.fn(async () => null),
    setItemAsync: jest.fn(async () => undefined),
    deleteItemAsync: jest.fn(async () => undefined),
}));

import {
    CANONICAL_ATTRIBUTES,
    isGovVerified,
    profileDisplayName,
} from '@/services/attributes';
import type { UserProfile } from '@/stores/profile';

const FALLBACK = 'Privasys User';

function profileWith(attrs: { key: string; value: string }[], displayName = FALLBACK): UserProfile {
    return {
        displayName,
        email: '',
        avatarUri: '',
        locale: 'en-GB',
        did: 'did:key:zTest',
        canonicalDid: 'did:web:privasys.id:users:test',
        pairwiseSeed: 'ff'.repeat(32),
        linkedProviders: [],
        attributes: attrs.map((a) => ({
            ...a,
            label: a.key,
            source: 'provider' as const,
            verified: false,
        })),
    } as unknown as UserProfile;
}

/** What the Personal Data screen offers as "Add:" chips. */
function addableKeys(existing: string[] = []): string[] {
    const have = new Set(existing);
    return CANONICAL_ATTRIBUTES.filter(
        (a) => !have.has(a.key) && a.key !== 'picture' && !isGovVerified(a.key),
    ).map((a) => a.key);
}

describe('manually addable attributes', () => {
    // Every key a passport read produces. Typing any of these would put an
    // unevidenced value under a key the rest of the wallet treats as evidenced.
    const GOV_ONLY = [
        'age_over_18',
        'age_over_21',
        'document_number',
        'document_type',
        'sex',
        'issuing_state',
        'doc_expiry',
        'place_of_birth',
        'personal_number',
        'given_name_id',
        'family_name_id',
        'birthdate_id',
        'nationality_id',
        'picture_id',
        'document_valid',
        'age_band',
    ];

    it.each(GOV_ONLY)('never offers %s', (key) => {
        expect(addableKeys()).not.toContain(key);
    });

    // The other half of the rule: this must not quietly become an empty list.
    it.each([
        'name',
        'nickname',
        'locale',
        'phone_number',
        // Self-asserted keys WITH a gov-verified twin. The disclosure path
        // distinguishes birthdate from birthdate_id, so asserting your own
        // date of birth stays legitimate.
        'birthdate',
        'nationality',
    ])('still offers %s', (key) => {
        expect(addableKeys()).toContain(key);
    });

    it('drops a key once the profile has it', () => {
        expect(addableKeys(['nickname'])).not.toContain('nickname');
    });

    it('classifies every canonical attribute as one or the other', () => {
        const offered = new Set(addableKeys());
        for (const a of CANONICAL_ATTRIBUTES) {
            if (a.key === 'picture') continue; // has its own avatar affordance
            expect(offered.has(a.key)).toBe(!isGovVerified(a.key));
        }
    });
});

describe('profileDisplayName', () => {
    it('uses an explicit Display Name above all else', () => {
        const p = profileWith([
            { key: 'name', value: 'Bee' },
            { key: 'given_name', value: 'bertrand' },
            { key: 'family_name', value: 'spams' },
        ]);
        expect(profileDisplayName(p, FALLBACK)).toBe('Bee');
    });

    // The reported case: Google gave a first and last name, the header did not.
    it('falls back to first and last name', () => {
        const p = profileWith([
            { key: 'given_name', value: 'bertrand' },
            { key: 'family_name', value: 'spams' },
        ]);
        expect(profileDisplayName(p, FALLBACK)).toBe('bertrand spams');
    });

    it('accepts a first name alone', () => {
        expect(profileDisplayName(profileWith([{ key: 'given_name', value: 'bertrand' }]), FALLBACK))
            .toBe('bertrand');
    });

    it('accepts a last name alone', () => {
        expect(profileDisplayName(profileWith([{ key: 'family_name', value: 'spams' }]), FALLBACK))
            .toBe('spams');
    });

    it('keeps a stored name when no attribute carries one', () => {
        expect(profileDisplayName(profileWith([], 'Stored Name'), FALLBACK)).toBe('Stored Name');
    });

    it('falls back to the placeholder for a wallet that knows nothing', () => {
        expect(profileDisplayName(profileWith([], ''), FALLBACK)).toBe(FALLBACK);
    });

    it('ignores whitespace-only values rather than rendering a blank name', () => {
        const p = profileWith([
            { key: 'name', value: '   ' },
            { key: 'given_name', value: 'bertrand' },
        ]);
        expect(profileDisplayName(p, FALLBACK)).toBe('bertrand');
    });
});
