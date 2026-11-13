import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SessionManager, deviceLabel } from '../src/session';

const store = new Map<string, string>();
(globalThis as unknown as { localStorage: Storage }).localStorage = {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => { store.set(k, v); },
    removeItem: (k: string) => { store.delete(k); },
    clear: () => store.clear(),
    key: () => null,
    length: 0,
} as Storage;

test('several wallets are remembered, the last used first', async () => {
    store.clear();
    const m = new SessionManager();
    m.saveDeviceHint('phone-a', 'wss://b', 'Ada’s iPhone');
    await new Promise((r) => setTimeout(r, 5));
    m.saveDeviceHint('phone-b', 'wss://b');
    assert.deepEqual(m.getDevices().map((d) => d.pushToken), ['phone-b', 'phone-a']);
    assert.equal(m.getDeviceHint()?.pushToken, 'phone-b');

    // Using the first again brings it to the front, and keeps its name and first date.
    const added = m.getDevices().find((d) => d.pushToken === 'phone-a')!.addedAt;
    await new Promise((r) => setTimeout(r, 5));
    m.saveDeviceHint('phone-a', '');
    const [first] = m.getDevices();
    assert.equal(first.pushToken, 'phone-a');
    assert.equal(first.label, 'Ada’s iPhone');
    assert.equal(first.addedAt, added);
    assert.equal(first.brokerUrl, 'wss://b');
    assert.equal(m.getDevices().length, 2);
});

test('forgetting one wallet leaves the others', () => {
    store.clear();
    const m = new SessionManager();
    m.saveDeviceHint('phone-a', 'wss://b');
    m.saveDeviceHint('phone-b', 'wss://b');
    m.forgetDevice('phone-a');
    assert.deepEqual(m.getDevices().map((d) => d.pushToken), ['phone-b']);
    m.forgetDevice('phone-b');
    assert.deepEqual(m.getDevices(), []);
    assert.equal(store.has('privasys_device_hints'), false);
});

test('a single hint stored by an older version reads as a list of one', () => {
    store.clear();
    store.set('privasys_device_hints', JSON.stringify({ pushToken: 'old', brokerUrl: 'wss://b', updatedAt: Date.UTC(2026, 10, 13) }));
    const m = new SessionManager();
    assert.deepEqual(m.getDevices().map((d) => d.pushToken), ['old']);
    assert.equal(deviceLabel(m.getDevices()[0]), 'Phone added 13 Nov');
    m.saveDeviceHint('new', 'wss://b', 'Work phone');
    assert.deepEqual(m.getDevices().map((d) => d.pushToken), ['new', 'old']);
    assert.equal(deviceLabel(m.getDevices()[0]), 'Work phone');
});

test('no more than eight wallets are kept', () => {
    store.clear();
    const m = new SessionManager();
    for (let i = 0; i < 12; i++) m.saveDeviceHint(`phone-${i}`, 'wss://b');
    assert.equal(m.getDevices().length, 8);
});
