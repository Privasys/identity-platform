// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { migrateDualTierAssurance, selfAssertedValue } from '@/services/attributes';
import type { ProfileAttribute, UserProfile } from '@/stores/profile';

function profileWith(attributes: ProfileAttribute[]): UserProfile {
    return { createdAt: 0, updatedAt: 0, attributes } as UserProfile;
}

function attr(key: string, value: string, source: ProfileAttribute['source']): ProfileAttribute {
    return { key, label: key, value, source, verified: source === 'document' };
}

describe('dual-tier assurance migration', () => {
    it('moves a passport reading off the self-asserted half', () => {
        const out = migrateDualTierAssurance(
            profileWith([attr('birthdate', '1980-01-01', 'document')])
        );
        expect(out.moved).toEqual(['birthdate']);
        expect(out.attributes.map((a) => a.key)).toEqual(['birthdate_id']);
        expect(out.attributes[0].value).toBe('1980-01-01');
    });

    it('drops the duplicate when the government key already holds it', () => {
        // Exactly what a wallet verified before AND after the split looks like:
        // the same date twice, both "certified by Privasys identity verifier".
        const out = migrateDualTierAssurance(
            profileWith([
                attr('birthdate', '1980-01-01', 'document'),
                attr('birthdate_id', '1980-01-01', 'document')
            ])
        );
        expect(out.dropped).toEqual(['birthdate']);
        expect(out.attributes.map((a) => a.key)).toEqual(['birthdate_id']);
    });

    it('leaves a typed value alone — that is what the free key now means', () => {
        const out = migrateDualTierAssurance(
            profileWith([attr('birthdate', '1980-01-01', 'manual')])
        );
        expect(out.moved).toEqual([]);
        expect(out.dropped).toEqual([]);
        expect(out.attributes.map((a) => a.key)).toEqual(['birthdate']);
    });

    it('covers every dual-tier pair, not just birthdate', () => {
        const out = migrateDualTierAssurance(
            profileWith([
                attr('given_name', 'BERTRAND', 'document'),
                attr('family_name', 'FOING', 'document'),
                attr('nationality', 'FRA', 'document')
            ])
        );
        expect(out.moved.sort()).toEqual(['family_name', 'given_name', 'nationality']);
        expect(out.attributes.map((a) => a.key).sort()).toEqual([
            'family_name_id',
            'given_name_id',
            'nationality_id'
        ]);
    });

    it('never touches a key with no government twin', () => {
        const out = migrateDualTierAssurance(
            profileWith([attr('document_number', 'X123', 'document')])
        );
        expect(out.moved).toEqual([]);
        expect(out.attributes.map((a) => a.key)).toEqual(['document_number']);
    });
});

describe('answering a self-asserted request', () => {
    it('answers from the certified reading when the free key is empty', () => {
        // The value, never the credential — so the relying party gets an
        // accurate date and no proof of it.
        const p = profileWith([attr('birthdate_id', '1980-01-01', 'document')]);
        expect(selfAssertedValue(p, 'birthdate')).toBe('1980-01-01');
    });

    it('prefers what the holder actually stored under the free key', () => {
        const p = profileWith([
            attr('birthdate', '1979-05-05', 'manual'),
            attr('birthdate_id', '1980-01-01', 'document')
        ]);
        expect(selfAssertedValue(p, 'birthdate')).toBe('1979-05-05');
    });

    it('does not answer from a twin that was never certified', () => {
        // A provider-supplied value is not a document reading, so it is not
        // the certified twin this fallback exists for.
        const p = profileWith([attr('birthdate_id', '1980-01-01', 'provider')]);
        expect(selfAssertedValue(p, 'birthdate')).toBeUndefined();
    });

    it('returns a stored value as-is for a key with no twin', () => {
        const p = profileWith([attr('document_number', 'X123', 'document')]);
        expect(selfAssertedValue(p, 'document_number')).toBe('X123');
    });

    it('has nothing to answer with when neither key holds anything', () => {
        expect(selfAssertedValue(profileWith([]), 'birthdate')).toBeUndefined();
    });
});
