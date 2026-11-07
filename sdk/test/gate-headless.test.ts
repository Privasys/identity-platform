import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitiseChoice, sanitiseGateState } from '../src/gate-headless';

test('a choice over postMessage is reduced to a well-formed one', () => {
    assert.deepEqual(sanitiseChoice({ method: 'wallet' }), { method: 'wallet' });
    assert.deepEqual(sanitiseChoice({ method: 'wallet', qr: true, extra: 1 }), { method: 'wallet', qr: true });
    assert.deepEqual(sanitiseChoice({ method: 'social', provider: 'microsoft', own: true }), { method: 'social', provider: 'microsoft', own: true });
    assert.deepEqual(sanitiseChoice({ method: 'social', provider: 'google', own: 'yes' }), { method: 'social', provider: 'google' });
    assert.equal(sanitiseChoice({ method: 'social', provider: 'Micro Soft' }), null);
    assert.equal(sanitiseChoice({ method: 'passkey' }), null);
    assert.equal(sanitiseChoice('wallet'), null);
    assert.equal(sanitiseChoice(null), null);
});

test('a state report carries only the named fields', () => {
    assert.deepEqual(sanitiseGateState({ state: 'qr-scanning', qr: 'https://privasys.id/r/abc', qrSvg: '<svg></svg>', secret: 'x' }),
        { state: 'qr-scanning', qr: 'https://privasys.id/r/abc', qrSvg: '<svg></svg>' });
    assert.deepEqual(sanitiseGateState({ state: 'error', error: 'Authentication cancelled' }), { state: 'error', error: 'Authentication cancelled' });
    assert.deepEqual(sanitiseGateState({ state: 'push-waiting', qrSvg: 'javascript:alert(1)' }), { state: 'push-waiting' });
    assert.equal(sanitiseGateState({ state: 'exploding' }), null);
    assert.equal(sanitiseGateState(undefined), null);
});
