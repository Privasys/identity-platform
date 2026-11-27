import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SessionManager, type SessionKey } from '../src/session';
import type { AuthSession } from '../src/types';

// The frame's storage: one per registrable domain, shared by every page under it.
const store = new Map<string, string>();
(globalThis as unknown as { localStorage: Storage }).localStorage = {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => { store.set(k, v); },
    removeItem: (k: string) => { store.delete(k); },
    clear: () => store.clear(),
    key: () => null,
    length: 0,
} as Storage;

const key = (clientId: string): SessionKey => ({ platform: 'aud', rpId: 'app', clientId });
const session = (token: string, at: number): AuthSession =>
    ({ token, rpId: 'app', origin: '', authenticatedAt: at, refreshToken: 'r-' + token, scope: 'openid' });

test('two clients sharing an rpId each keep their own session', () => {
    store.clear();
    const m = new SessionManager();
    m.store(key('client-a'), session('ta', 1));
    assert.equal(m.get(key('client-b')), undefined, "client b was given client a's session");
    m.store(key('client-b'), session('tb', 2));

    assert.equal(m.get(key('client-a'))?.token, 'ta', "client b's sign-in replaced client a's session");
    assert.equal(m.get(key('client-b'))?.token, 'tb');

    m.remove(key('client-b'));
    assert.equal(m.get(key('client-b')), undefined);
    assert.equal(m.get(key('client-a'))?.token, 'ta', "client b's sign-out removed client a's session");
});

test('a renewal replaces the session of its own client only', () => {
    store.clear();
    const m = new SessionManager();
    m.store(key('client-a'), session('a1', 1));
    m.store(key('client-b'), session('b1', 2));
    m.store(key('client-a'), session('a2', 3));
    assert.deepEqual(m.getAll().map((s) => s.token).sort(), ['a2', 'b1']);
});

test('a session is stored under its key, whatever it says itself', () => {
    store.clear();
    const m = new SessionManager();
    m.store(key('client-a'), { ...session('t', 1), clientId: 'client-z', rpId: 'other', platform: 'elsewhere' });
    const [stored] = m.getAll();
    assert.deepEqual([stored.platform, stored.rpId, stored.clientId], ['aud', 'app', 'client-a']);
});

test('a stored record without platform, client or scope is not a session', () => {
    store.clear();
    const full = { ...session('t', 1), platform: 'aud', clientId: 'client-a' };
    const { platform: _p, ...noPlatform } = full;
    const { clientId: _c, ...noClient } = full;
    const { scope: _s, ...noScope } = full;
    localStorage.setItem('privasys_sessions', JSON.stringify([noPlatform, noClient, noScope, full]));
    const m = new SessionManager();
    assert.equal(m.getAll().length, 1);
    assert.equal(m.get(key('client-a'))?.token, 't');
});

test('a session with no platform or client to be found by is refused loudly', () => {
    store.clear();
    const m = new SessionManager();
    assert.throws(() => m.store({ platform: '', rpId: 'app', clientId: 'client-a' }, session('t', 1)));
    assert.throws(() => m.store({ platform: 'aud', rpId: 'app', clientId: '' }, session('t', 1)));
    assert.equal(m.getAll().length, 0);
});
