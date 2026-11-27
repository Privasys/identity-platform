import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
    appHost, approvalReason, channelState, cloneableInit, extractDisclosures, parseView, sessionOf, widenedBy,
} from '../src/client/session';
import { Channel } from '../src/client/app-channel';

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (claims: Record<string, unknown>) => `${b64({ alg: 'none' })}.${b64(claims)}.x`;
const vc = (claims: Record<string, unknown>) => `${jwt(claims)}~`;

test('a session is built from what the frame reports', () => {
    const token = jwt({ exp: 2_000_000_000, sid: 's1' });
    const s = sessionOf({ token, method: 'wallet' }, null);
    assert.deepEqual(s, { token, method: 'wallet', expiresAt: 2_000_000_000_000 });
});

test('a renewal of the same sign-in keeps its disclosures; another sign-in does not', () => {
    const first = jwt({ exp: 1, sid: 's1', age_over_18: vc({ claim: 'age_over_18', value: true, assurance: 'gov', iss: 'https://v.test' }) });
    const signedIn = sessionOf({ token: first, method: 'wallet' }, null);
    assert.equal(signedIn.disclosures?.length, 1);
    assert.equal(signedIn.disclosures?.[0].claim, 'age_over_18');
    const renewed = sessionOf({ token: jwt({ exp: 2, sid: 's1' }), method: 'wallet' }, signedIn);
    assert.equal(renewed.disclosures, signedIn.disclosures);
    const other = sessionOf({ token: jwt({ exp: 2, sid: 's2' }), method: 'wallet' }, signedIn);
    assert.equal(other.disclosures, undefined);
});

test('a claim that only looks like a credential is not a disclosure', () => {
    assert.equal(extractDisclosures(jwt({ note: 'eyJ.notajws~' })), undefined);
    assert.equal(extractDisclosures('garbage'), undefined);
});

test('a frame report is checked', () => {
    assert.equal(parseView(null), null);
    assert.equal(parseView({ token: '' }), null);
    assert.deepEqual(parseView({ token: 't', method: 'social' }), { token: 't', method: 'social', requestedAttributes: [], scope: '' });
    assert.equal(parseView({ token: 't', method: 'other' })?.method, 'passkey');
});

test('a wider request is told apart from the recorded one', () => {
    const view = { token: 't', method: 'wallet' as const, requestedAttributes: ['email'], scope: 'openid offline_access' };
    assert.equal(widenedBy({ attributes: ['email'] }, view), null);
    assert.deepEqual(widenedBy({ attributes: ['email', 'birthdate_id'] }, view), ['birthdate_id']);
    assert.deepEqual(widenedBy({ scope: ['openid', 'offline_access', 'profile'] }, view), ['profile']);
    // A session that recorded no scope is not widened by one.
    assert.equal(widenedBy({ scope: ['openid', 'profile'] }, { ...view, scope: '' }), null);
});

test('a sealed state reads as a channel state', () => {
    assert.equal(channelState('ok'), 'ok');
    assert.equal(channelState('recovering'), 'reconnecting');
    assert.equal(channelState('reapproval-required'), 'signed-out');
    assert.equal(channelState('signed-out'), 'signed-out');
});

test('only a missing or refused approval asks the wallet', () => {
    assert.equal(approvalReason('no-voucher'), null);
    assert.equal(approvalReason('rejected', 'enc-changed'), 'enc-changed');
    assert.equal(approvalReason('rejected'), 'rejected');
    assert.equal(approvalReason('unavailable'), undefined);
    assert.equal(approvalReason('no-session'), undefined);
});

test('an app is named by its host', () => {
    assert.equal(appHost(' My-App.apps.privasys.org '), 'my-app.apps.privasys.org');
    assert.equal(appHost('localhost:8443'), 'localhost:8443');
    for (const bad of ['https://x.test', 'x.test/path', '', 'a..b', '-x.test']) {
        assert.throws(() => appHost(bad), /not a host name/, bad);
    }
});

test('a request init crosses postMessage as plain headers', () => {
    assert.equal(cloneableInit(undefined), undefined);
    assert.deepEqual(cloneableInit({ headers: new Headers({ 'X-A': '1' }), signal: new AbortController().signal }), { headers: { 'x-a': '1' } });
    assert.deepEqual(cloneableInit({ headers: [['X-B', '2']] }), { headers: { 'X-B': '2' } });
});

test('a channel reports its state and refuses requests once closed', async () => {
    const ch = new Channel('x.test');
    assert.equal(ch.state, 'signed-out');
    await assert.rejects(ch.request('GET', '/'), /call app\(\) again/);
    const states: string[] = [];
    ch.onState((s) => states.push(s));
    const calls: string[] = [];
    ch.use({
        kind: 'direct',
        request: async (m, p) => { calls.push(`${m} ${p}`); return { status: 200, headers: {}, body: new Uint8Array(), transport: 'direct' }; },
        stream: async () => { throw new Error('unused'); },
        openWebSocket: () => { throw new Error('unused'); },
    });
    assert.equal(ch.transport, 'direct');
    assert.equal(ch.live('direct'), true);
    assert.equal(ch.live('sealed'), false);
    await ch.request('GET', '/me');
    ch.setState('reconnecting');
    ch.setState('signed-out');
    assert.deepEqual(states, ['ok', 'reconnecting', 'signed-out']);
    assert.deepEqual(calls, ['GET /me']);
    assert.equal(ch.live('direct'), false);
});
