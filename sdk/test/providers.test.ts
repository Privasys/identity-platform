import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
    SOCIAL_PROVIDERS,
    providerButtonLabel,
    providerName,
    sanitiseDisplayNames,
    sanitiseIcons,
    sanitiseOwn,
    sanitiseProviders,
    selectProviders,
} from '../src/providers';

test('the adopter list is reduced to known providers, in order, without duplicates', () => {
    assert.deepEqual(sanitiseProviders(['microsoft']), ['microsoft']);
    assert.deepEqual(sanitiseProviders(['Google', ' microsoft ', 'google']), ['google', 'microsoft']);
    assert.deepEqual(sanitiseProviders(['facebook', 'microsoft', 42, null]), ['microsoft']);
    assert.deepEqual(sanitiseProviders([...SOCIAL_PROVIDERS]), [...SOCIAL_PROVIDERS]);
});

test('anything that is not a list of known providers means no preference', () => {
    for (const bad of [undefined, null, 'microsoft', {}, [], ['facebook'], [1, 2]]) {
        assert.equal(sanitiseProviders(bad), undefined, JSON.stringify(bad));
    }
});

test('without a preference every available provider is offered as published', () => {
    assert.deepEqual(selectProviders(['github', 'google', 'microsoft'], undefined), ['github', 'google', 'microsoft']);
    assert.deepEqual(selectProviders([], undefined), []);
});

test('a preference restricts and orders the available providers', () => {
    assert.deepEqual(selectProviders(['github', 'google', 'microsoft', 'linkedin'], ['microsoft']), ['microsoft']);
    assert.deepEqual(selectProviders(['github', 'google', 'microsoft'], ['microsoft', 'google']), ['microsoft', 'google']);
});

test('a requested provider the identity provider lacks is left out, not shown dead', () => {
    assert.deepEqual(selectProviders(['github', 'google'], ['microsoft', 'google']), ['google']);
});

test('a preference that matches nothing falls back to the published list, never to no button', () => {
    assert.deepEqual(selectProviders(['github', 'google'], ['microsoft']), ['github', 'google']);
    assert.deepEqual(selectProviders([], ['microsoft']), []);
});

test('button labels are brand-correct and carry the call to action only when alone', () => {
    assert.equal(providerName('microsoft'), 'Microsoft');
    assert.equal(providerName('github'), 'GitHub');
    assert.equal(providerName('okta'), 'okta');
    assert.equal(providerButtonLabel('microsoft', true), 'Sign in with Microsoft');
    assert.equal(providerButtonLabel('linkedin', true), 'Sign in with LinkedIn');
    assert.equal(providerButtonLabel('microsoft', false), 'Microsoft');
});

test('a client\'s own registration names the button', () => {
    assert.equal(providerButtonLabel('microsoft', false, 'Contoso Government'), 'Sign in with Contoso Government');
    assert.equal(providerButtonLabel('microsoft', false), 'Microsoft');
    assert.deepEqual(sanitiseDisplayNames({ microsoft: ' Contoso ', other: 7, long: 'x'.repeat(65) }), { microsoft: 'Contoso' });
    assert.equal(sanitiseDisplayNames({}), undefined);
    assert.equal(sanitiseDisplayNames('x'), undefined);
});

test('icons are kept only as https addresses without credentials, at most 512 characters', () => {
    assert.deepEqual(
        sanitiseIcons({ microsoft: 'https://www.gov.im/crest.svg', github: 'http://x.example/i.svg' }),
        { microsoft: 'https://www.gov.im/crest.svg' },
    );
    for (const bad of [undefined, null, 'https://x.example/i.svg', [], { microsoft: 42 }, { microsoft: 'javascript:alert(1)' },
        { microsoft: 'https://u:p@x.example/i.svg' }, { microsoft: 'https://' + 'a'.repeat(510) }, { microsoft: 'not a url' }]) {
        assert.equal(sanitiseIcons(bad), undefined, JSON.stringify(bad));
    }
});

test('own registrations keep known providers with a name and an https icon', () => {
    assert.equal(sanitiseOwn(undefined), undefined);
    assert.equal(sanitiseOwn({ provider: 'microsoft' }), undefined);
    assert.deepEqual(
        sanitiseOwn([
            { provider: 'microsoft', display_name: ' Contoso Staff ', icon: 'https://contoso.example/logo.svg' },
            { provider: 'microsoft', display_name: 'No icon' },
            { provider: 'microsoft', display_name: 'Bad icon', icon: 'http://plain.example/x.png' },
            { provider: 'teams', display_name: 'Unknown provider' },
            { provider: 'google', display_name: '' },
            { provider: 'google', display_name: 'x'.repeat(65) },
            'nonsense',
        ]),
        [
            { provider: 'microsoft', displayName: 'Contoso Staff', iconUrl: 'https://contoso.example/logo.svg' },
            { provider: 'microsoft', displayName: 'No icon' },
            { provider: 'microsoft', displayName: 'Bad icon' },
        ],
    );
});
