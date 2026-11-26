// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

jest.mock('@/utils/storage', () => ({
    getItemAsync: jest.fn(async () => null),
    setItemAsync: jest.fn(async () => {}),
}));
jest.mock('@/i18n', () => ({ currentLocale: () => 'fr' }));

import { attributeInputProps } from '@/utils/attribute-input';
import { getAttributeValues, isCodedAttribute } from '@/services/value-sets';

describe('attributeInputProps', () => {
    it('never capitalises a name or an address for the holder', () => {
        for (const key of ['name', 'given_name', 'family_name', 'nickname', 'address']) {
            expect(attributeInputProps(key).autoCapitalize).toBe('none');
        }
    });

    it('asks the system for the holder\'s own email, with predictions off', () => {
        expect(attributeInputProps('email')).toMatchObject({
            autoComplete: 'email',
            textContentType: 'emailAddress',
            autoCorrect: false,
        });
    });

    it('offers no autofill where a code is stored', () => {
        for (const key of ['billing_country', 'nationality', 'locale']) {
            expect(attributeInputProps(key).autoComplete).toBe('off');
        }
    });
});

describe('coded value sets', () => {
    it('knows which attributes are picked from a list', () => {
        expect(isCodedAttribute('nationality')).toBe(true);
        expect(isCodedAttribute('billing_country')).toBe(true);
        expect(isCodedAttribute('locale')).toBe(true);
        expect(isCodedAttribute('email')).toBe(false);
        expect(isCodedAttribute('birthdate')).toBe(false);
    });

    it('asks privasys.id for the names in the wallet language', async () => {
        const fetchMock = jest.fn(async () => ({
            ok: true,
            json: async () => ({ values: [{ value: 'FR', label: 'France' }] }),
        }));
        (global as any).fetch = fetchMock;
        const values = await getAttributeValues('billing_country');
        expect(values).toEqual([{ value: 'FR', label: 'France' }]);
        expect(String((fetchMock.mock.calls[0] as unknown[])[0])).toMatch(/\/referential\/country\.json\?lang=fr$/);
    });
});
