// A page gets only its own platform's sessions: pages of a production and a
// test platform share the frame's storage under one registrable domain.
// Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parsePlatforms, platformScopeOf } from '../src/platforms';
import { SessionManager, sessionKeyId, type SessionKey } from '../src/session';
import type { AuthSession } from '../src/types';

const LIST = { platforms: [{ audience: 'aud-prod' }, { audience: 'aud-test', domains: ['test.example.org'] }, { audience: 'aud-deep', domains: ['deep.test.example.org'] }] };

test('a page is placed by its host, at a dot, longest domain first', () => {
    const list = parsePlatforms(LIST)!;
    const at = (o: string) => platformScopeOf(list, o)?.platform;
    assert.equal(at('https://www.example.org'), 'aud-prod');
    assert.equal(at('https://test.example.org'), 'aud-test');
    assert.equal(at('https://App.Test.Example.org'), 'aud-test');
    assert.equal(at('https://x.deep.test.example.org'), 'aud-deep');
    assert.equal(at('https://nottest.example.org'), 'aud-prod');
    assert.equal(at('https://test.example.org.evil.com'), 'aud-prod');
    assert.equal(platformScopeOf(list, 'not a url'), null);
});

test('a list that is not one is refused', () => {
    assert.equal(parsePlatforms(null), null);
    assert.equal(parsePlatforms({ platforms: [{ audience: 'a', domains: ['x.org'] }] }), null); // no default
    assert.equal(parsePlatforms({ platforms: [{ audience: 'a' }, { audience: 'b' }] }), null); // two defaults
    assert.equal(parsePlatforms({ platforms: [{ audience: 'a' }, { audience: 'b', domains: ['*.x.org'] }] }), null);
    assert.equal(parsePlatforms({ platforms: [{ audience: 'a b' }] }), null);
});

// ── Sessions ────────────────────────────────────────────────────────────

const store = new Map<string, string>();
(globalThis as unknown as { localStorage: Storage }).localStorage = {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
    key: () => null,
    length: 0,
};

const session = (extra: Partial<AuthSession> = {}): AuthSession => ({
    token: 't', rpId: 'privasys.id', origin: '', authenticatedAt: Date.now(), clientId: 'client-a', scope: 'openid', ...extra,
});

/** The key a page at `origin` reaches for a client. */
function keyAt(origin: string, clientId = 'client-a'): SessionKey {
    return { platform: platformScopeOf(parsePlatforms(LIST)!, origin)!.platform, rpId: 'privasys.id', clientId };
}

test('a test page never sees, replaces or removes the production session', () => {
    store.clear();
    const m = new SessionManager();
    const prod = keyAt('https://portal.example.org');
    const dev = keyAt('https://portal.test.example.org');
    m.store(prod, session({ token: 'prod' }));
    assert.equal(m.get(dev), undefined);

    m.store(dev, session({ token: 'dev' }));
    assert.equal(m.get(prod)!.platform, 'aud-prod');
    assert.equal(m.get(dev)!.platform, 'aud-test');
    assert.equal(m.getAll().length, 2);

    m.remove(dev);
    assert.equal(m.get(prod)?.token, 'prod');
    assert.equal(m.get(dev), undefined);
});

test('a session that recorded no platform is given to no page', () => {
    store.clear();
    localStorage.setItem('privasys_sessions', JSON.stringify([session()]));
    assert.equal(new SessionManager().get(keyAt('https://portal.example.org')), undefined);
});

test('the same client on two platforms renews under two names', () => {
    const prod = keyAt('https://portal.example.org');
    const dev = keyAt('https://portal.test.example.org');
    assert.notEqual(sessionKeyId(prod), sessionKeyId(dev));
    assert.notEqual(sessionKeyId(prod), sessionKeyId({ ...prod, clientId: 'client-b' }));
});
