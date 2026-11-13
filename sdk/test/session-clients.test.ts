import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SessionManager } from '../src/session';
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

const session = (token: string, clientId: string | undefined, at: number): AuthSession =>
    ({ token, rpId: 'app', origin: '', authenticatedAt: at, clientId, refreshToken: 'r-' + token });

test('two clients sharing an rpId each keep their own session', () => {
    store.clear();
    const a = new SessionManager();
    a.forClient('client-a');
    a.store(session('ta', 'client-a', 1));

    const b = new SessionManager();
    b.forClient('client-b');
    assert.equal(b.get('app'), undefined, "client b was given client a's session");
    b.store(session('tb', 'client-b', 2));

    assert.equal(a.get('app')?.token, 'ta', "client b's sign-in replaced client a's session");
    assert.equal(b.get('app')?.token, 'tb');

    b.remove('app');
    assert.equal(b.get('app'), undefined);
    assert.equal(a.get('app')?.token, 'ta', "client b's sign-out removed client a's session");
});

test('a renewal replaces the session of its own client only', () => {
    store.clear();
    const m = new SessionManager();
    m.store(session('a1', 'client-a', 1));
    m.store(session('b1', 'client-b', 2));
    m.store(session('a2', 'client-a', 3));
    assert.deepEqual(m.getAll().map((s) => s.token).sort(), ['a2', 'b1']);
});

test('a page that names no client gets the most recent session for the rpId', () => {
    store.clear();
    const m = new SessionManager();
    m.store(session('old', 'client-a', 1));
    m.store(session('new', 'client-b', 2));
    assert.equal(m.get('app')?.token, 'new');
    m.forClient('client-a');
    assert.equal(m.get('app')?.token, 'old');
    m.forClient(null);
    assert.equal(m.get('app')?.token, 'new');
});
