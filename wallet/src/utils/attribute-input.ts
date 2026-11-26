// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Text-input settings for a holder typing one of their OWN attributes:
 * keyboard, capitalisation and the platform autofill hints.
 *
 * The autofill hints make the system suggest the holder's own data: on iOS
 * the user's own contact card ("My Card") and iCloud Keychain, on Android the
 * autofill service (the Google accounts on the device, saved addresses).
 * Autocorrect is turned off where the keyboard's general predictions would
 * offer other people's values (email, phone). No platform lets an app pick
 * the suggestion list itself; these hints are the closest there is.
 *
 * Coded keys (nationality, billing_country, locale) and the date of birth are
 * normally chosen from a list or a calendar, not typed (components/ValueList,
 * components/BirthdateField). Their entries below only cover a text field
 * that still shows one, and give no autofill, because the system would insert
 * a name ("France") where a code ("FR") is stored.
 */

import type { TextInputProps } from 'react-native';

export type AttributeInputProps = Pick<
    TextInputProps,
    'keyboardType' | 'autoCapitalize' | 'autoComplete' | 'textContentType' | 'autoCorrect' | 'spellCheck' | 'maxLength'
>;

const NO_AUTOFILL: AttributeInputProps = { autoComplete: 'off', textContentType: 'none' };

export function attributeInputProps(key: string | null | undefined): AttributeInputProps {
    switch (key) {
        case 'email':
            return {
                keyboardType: 'email-address',
                autoCapitalize: 'none',
                autoComplete: 'email',
                textContentType: 'emailAddress',
                autoCorrect: false,
                spellCheck: false,
            };
        case 'phone_number':
            return {
                keyboardType: 'phone-pad',
                autoCapitalize: 'none',
                autoComplete: 'tel',
                textContentType: 'telephoneNumber',
                autoCorrect: false,
            };
        // Names and addresses are typed as the holder writes them: no automatic
        // capitals. Upper-case names are what an ID document says (the *_id
        // twins), not the norm for the everyday ones.
        case 'name':
            return { autoCapitalize: 'none', autoComplete: 'name', textContentType: 'name' };
        case 'given_name':
            return { autoCapitalize: 'none', autoComplete: 'name-given', textContentType: 'givenName' };
        case 'family_name':
            return { autoCapitalize: 'none', autoComplete: 'name-family', textContentType: 'familyName' };
        case 'nickname':
            return { autoCapitalize: 'none', autoComplete: 'nickname', textContentType: 'nickname' };
        case 'address':
            return { autoCapitalize: 'none', autoComplete: 'postal-address', textContentType: 'fullStreetAddress' };
        case 'birthdate':
            return {
                keyboardType: 'numbers-and-punctuation',
                autoCapitalize: 'none',
                autoComplete: 'birthdate-full',
                textContentType: 'birthdate',
                autoCorrect: false,
            };
        case 'billing_country':
            return { ...NO_AUTOFILL, autoCapitalize: 'characters', autoCorrect: false, spellCheck: false, maxLength: 2 };
        case 'nationality':
            return { ...NO_AUTOFILL, autoCapitalize: 'words', autoCorrect: false };
        case 'locale':
            return { ...NO_AUTOFILL, autoCapitalize: 'none', autoCorrect: false, spellCheck: false };
        default:
            return { ...NO_AUTOFILL, autoCapitalize: 'sentences' };
    }
}
