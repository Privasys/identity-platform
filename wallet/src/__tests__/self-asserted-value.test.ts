// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { selfAssertedValue } from '@/services/attributes';
import type { ProfileAttribute, UserProfile } from '@/stores/profile';

function profileWith(attributes: ProfileAttribute[]): UserProfile {
    return { createdAt: 0, updatedAt: 0, attributes } as UserProfile;
}

function attr(key: string, value: string, source: ProfileAttribute['source']): ProfileAttribute {
    return { key, label: key, value, source, verified: source === 'document' };
}

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
