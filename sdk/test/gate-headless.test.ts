import { test } from 'node:test';
import assert from 'node:assert/strict';
import { finishOnSuccess, sanitiseChoice, sanitiseGateState } from '../src/gate-headless';

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

test('a headless gate finishes a first wallet sign-in without asking to trust the device', () => {
    // The QR sign-in on an untrusted device: a visible gate asks.
    assert.deepEqual(finishOnSuccess({ pushToken: 'p' }), { now: false });
    // A headless gate cannot ask, so it finishes, and does not remember the device.
    assert.deepEqual(finishOnSuccess({ pushToken: 'p', headless: true }), { now: true, trust: false });
    // Already trusted, or signed in over a push: finish and keep the trust.
    assert.deepEqual(finishOnSuccess({ pushToken: 'p', deviceTrusted: true }), { now: true, trust: true });
    assert.deepEqual(finishOnSuccess({ pushToken: 'p', viaPush: true, headless: true }), { now: true, trust: true });
    // No wallet involved: nothing to trust.
    assert.deepEqual(finishOnSuccess({}), { now: true, trust: false });
});
