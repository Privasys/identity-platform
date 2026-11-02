import { test } from 'node:test';
import assert from 'node:assert/strict';
import { alternativeOrder, displayAppName } from '../src/gate';

test('a slug is shown as capitalised words', () => {
    assert.equal(displayAppName('diom-dar'), 'Diom Dar');
    assert.equal(displayAppName('my_app'), 'My App');
    assert.equal(displayAppName('globaml'), 'Globaml');
});

test('a name written for people is shown as written', () => {
    assert.equal(displayAppName('Isle of Man Data Asset Register'), 'Isle of Man Data Asset Register');
    assert.equal(displayAppName('GlobAML'), 'GlobAML');
    assert.equal(displayAppName('  Privasys Drive '), 'Privasys Drive');
});

test('the alternatives follow the order the adopter listed', () => {
    assert.deepEqual(alternativeOrder(['social', 'passkey']), ['social', 'passkey']);
    assert.deepEqual(alternativeOrder(['wallet', 'passkey', 'social']), ['passkey', 'social']);
    assert.deepEqual(alternativeOrder(['social']), ['social']);
    assert.deepEqual(alternativeOrder(['wallet']), []);
});

test('without a list the passkey comes first', () => {
    assert.deepEqual(alternativeOrder(undefined), ['passkey', 'social']);
});
