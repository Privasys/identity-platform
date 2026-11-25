// A page gets only its own platform's sessions: pages of a production and a
// test platform share the frame's storage under one registrable domain.
// Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parsePlatforms, platformScopeOf } from '../src/platforms';
import { SessionManager, sessionPlatform } from '../src/session';
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

const jwt = (aud: string) => `x.${Buffer.from(JSON.stringify({ aud })).toString('base64url')}.y`;
const session = (aud: string, extra: Partial<AuthSession> = {}): AuthSession => ({
    token: jwt(aud), rpId: 'privasys.id', origin: '', authenticatedAt: Date.now(), clientId: 'client-a', ...extra,
});

function scoped(origin: string) {
    const m = new SessionManager();
    m.forClient('client-a');
    m.forPlatform(platformScopeOf(parsePlatforms(LIST)!, origin));
    return m;
}

test("a test page never sees, replaces or removes the production session", () => {
    store.clear();
    const prod = scoped('https://portal.example.org');
    const dev = scoped('https://portal.test.example.org');
    prod.store(session('aud-prod'));
    assert.equal(dev.get('privasys.id'), undefined);

    dev.store(session('aud-test'));
    assert.equal(sessionPlatform(prod.get('privasys.id')!, platformScopeOf(parsePlatforms(LIST)!, 'https://a.example.org')!), 'aud-prod');
    assert.equal(prod.get('privasys.id')!.platform, 'aud-prod');
    assert.equal(dev.get('privasys.id')!.platform, 'aud-test');
    assert.equal(prod.getAll().length, 2);

    dev.remove('privasys.id');
    assert.ok(prod.get('privasys.id'));
    assert.equal(dev.get('privasys.id'), undefined);
});

test('a session stored before platforms were recorded is placed by its token', () => {
    store.clear();
    const legacy = new SessionManager();
    legacy.store(session('aud-prod'));
    legacy.store(session('aud-test', { clientId: 'client-b' }));
    legacy.store(session('app:0123', { clientId: 'client-c' }));
    const dev = scoped('https://portal.test.example.org');
    assert.equal(dev.get('privasys.id'), undefined); // client-a's token is production's
    dev.forClient('client-b');
    assert.ok(dev.get('privasys.id'));
    const prod = scoped('https://portal.example.org');
    prod.forClient('client-c');
    assert.ok(prod.get('privasys.id')); // an app audience reads as the default
});

test('a renewal reads and removes its own chain, whichever client was named last', () => {
    store.clear();
    const m = scoped('https://portal.example.org');
    m.store(session('aud-prod'));
    m.forClient('client-b');
    m.store(session('aud-prod', { clientId: 'client-b' }));
    // The page last named client-b; a timer armed for client-a still finds client-a.
    assert.equal(m.getFor('privasys.id', 'client-a')?.clientId, 'client-a');
    m.removeFor('privasys.id', 'client-a');
    assert.equal(m.getFor('privasys.id', 'client-a'), undefined);
    assert.equal(m.get('privasys.id')?.clientId, 'client-b');
});

test('with no platform known, nothing matches and nothing is stored', () => {
    store.clear();
    new SessionManager().store(session('aud-prod'));
    const m = new SessionManager();
    m.forClient('client-a');
    m.forPlatform(null);
    assert.equal(m.get('privasys.id'), undefined);
    m.store(session('aud-prod'));
    assert.equal(new SessionManager().getAll().length, 1);
});
