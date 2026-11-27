// AuthFrame.app(), end to end against a mocked identity provider and mocked
// enclave hosts.
//  - A passkey session reaches an app directly: a request carries a bearer
//    token minted for the channel's audience, the same host gives the same
//    channel, an audience is required, and signing out closes the channel.
//  - A wallet session reaches an app sealed: app() resumes from the
//    session's approval for the host; with none, it calls onApproval(null),
//    asks the wallet by push (voucher-only, for that host) and resumes again;
//    an enclave that refuses the approval names why (onApproval('enc-changed')).
// Run after `npm run build`: `node e2e/app-channel.cjs`.
const fs = require('fs');
const assert = require('assert/strict');
const { chromium } = require(process.cwd() + '/node_modules/playwright');

const frameBundle = fs.readFileSync('dist/privasys-auth-frame.iife.js', 'utf8');
const clientBundle = fs.readFileSync('dist/privasys-auth-client.iife.js', 'utf8');
const framePage = '<!doctype html><html><head><title>auth</title></head><body><script src="/auth/privasys-auth-frame.iife.js"></script></body></html>';
const sitePage = '<!doctype html><html><body><script src="/client.js"></script></body></html>';

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwtFor = (aud, n) => `${b64({ alg: 'none' })}.${b64({ aud, exp: Math.floor(Date.now() / 1000) + 900, sid: 'sid-1', n })}.x`;
const claims = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString());
const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': 'authorization, content-type',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
};

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  let refreshes = 0;
  const appCalls = [];
  const encauthCalls = [];
  const notified = [];
  const bootstraps = [];
  await ctx.route('https://**/*', async (r) => {
    const req = r.request();
    const u = new URL(req.url());
    if (req.method() === 'OPTIONS') return r.fulfill({ status: 204, headers: CORS, body: '' });
    if (u.host === 'idp.test') {
      if (u.pathname === '/auth/') return r.fulfill({ contentType: 'text/html', body: framePage });
      if (u.pathname === '/auth/privasys-auth-frame.iife.js') return r.fulfill({ contentType: 'text/javascript', body: frameBundle });
      if (u.pathname === '/wallet/platforms') return r.fulfill({ contentType: 'application/json', body: '{"platforms":[{"audience":"privasys-platform"}]}' });
      if (u.pathname === '/session/client-origin') return r.fulfill({ contentType: 'application/json', body: '{"allowed":true}' });
      if (u.pathname === '/token') {
        refreshes++;
        const aud = /audience:(\S+)/.exec(new URLSearchParams(req.postData() || '').get('scope') || '');
        return r.fulfill({ contentType: 'application/json', body: JSON.stringify({
          access_token: jwtFor(aud ? aud[1] : 'privasys-platform', refreshes), refresh_token: `rt-${refreshes}`, token_type: 'Bearer', expires_in: 900 }) });
      }
      if (u.pathname === '/sessions/sid-1/encauth') {
        const host = u.searchParams.get('host');
        encauthCalls.push({ host, auth: req.headers()['authorization'] || '' });
        // enc.test has no approval until the wallet answers the push;
        // enc2.test has one, which its enclave refuses.
        const approved = host === 'enc2.test' || notified.some((b) => b.appHost === host);
        if (!approved) return r.fulfill({ status: 404, contentType: 'application/json', body: '{"error":"no voucher"}' });
        const round = notified.filter((b) => b.appHost === host).length;
        return r.fulfill({ contentType: 'application/json', body: JSON.stringify({ v: 1, payload: `p${round}`, hw_sig: '', idp_sig: '' }) });
      }
      return r.fulfill({ contentType: 'application/json', body: '{}' });
    }
    if (u.host === 'broker.test' && u.pathname === '/notify') {
      notified.push(JSON.parse(req.postData() || '{}'));
      return r.fulfill({ status: 200, headers: CORS, contentType: 'application/json', body: '{}' });
    }
    if (u.pathname === '/__privasys/session-bootstrap') {
      bootstraps.push(u.host);
      // enc.test is still booting; enc2.test's platform changed.
      if (u.host === 'enc.test') return r.fulfill({ status: 503, headers: CORS, body: '' });
      return r.fulfill({ headers: CORS, contentType: 'application/json', body: JSON.stringify({ encauth_reject: 'enc-changed' }) });
    }
    if (u.host === 'app.test') {
      appCalls.push({ path: u.pathname, auth: req.headers()['authorization'] || '' });
      return r.fulfill({ headers: CORS, contentType: 'application/json', body: '{"ok":true}' });
    }
    if (u.host === 'site-a.test') {
      if (u.pathname === '/client.js') return r.fulfill({ contentType: 'text/javascript', body: clientBundle });
      return r.fulfill({ contentType: 'text/html', body: sitePage });
    }
    return r.fulfill({ status: 404, body: '' });
  });

  const page = await ctx.newPage();
  await page.goto('https://site-a.test/');
  const base = { rpId: 'privasys.id', authenticatedAt: Date.now(), refreshToken: 'rt-0', scope: 'openid offline_access', platform: 'privasys-platform' };
  await page.evaluate(() => new Promise((resolve) => {
    const f = document.createElement('iframe');
    f.src = 'https://idp.test/auth/?seed';
    f.onload = () => resolve();
    document.body.append(f);
    window.__seed = f;
  }));
  const seedFrame = page.frames().find((f) => f.url() === 'https://idp.test/auth/?seed');
  await seedFrame.evaluate((s) => localStorage.setItem('privasys_sessions', JSON.stringify(s)), [
    { ...base, clientId: 'passkey-site', token: jwtFor('privasys-platform', 0), method: 'passkey' },
    { ...base, clientId: 'wallet-site', token: jwtFor('privasys-platform', 0), method: 'wallet', wallet: true,
      pushToken: 'ExponentPushToken[x]', brokerUrl: 'wss://broker.test/relay' },
  ]);
  await page.evaluate(() => window.__seed.remove());

  // ── Direct ──
  const direct = await page.evaluate(async () => {
    const auth = new Privasys.AuthFrame({ authOrigin: 'https://idp.test', clientId: 'passkey-site', appName: 'app' });
    window.direct = auth;
    await auth.connect();
    const noAudience = await auth.app('other.test').then(() => 'opened', (e) => e.message);
    const ch = await auth.app('app.test', { audience: 'app:abc' });
    const again = await auth.app('APP.test');
    const res = await ch.request('GET', '/me');
    const states = [];
    ch.onState((s) => states.push(s));
    const badHost = await auth.app('https://app.test/x').then(() => 'opened', (e) => e.message);
    await auth.signOut();
    return {
      noAudience, same: ch === again, transport: ch.transport, status: res.status,
      body: new TextDecoder().decode(res.body), states, after: ch.state, badHost,
    };
  });
  assert.match(direct.noAudience, /needs an audience/, 'a direct channel needs an audience: ' + direct.noAudience);
  assert.equal(direct.same, true, 'the same host gives the same channel');
  assert.equal(direct.transport, 'direct', 'a passkey session reaches the app directly');
  assert.equal(direct.status, 200);
  assert.equal(direct.body, '{"ok":true}');
  assert.equal(appCalls.length, 1, 'one request reached the app');
  const bearer = appCalls[0].auth.replace(/^Bearer /, '');
  assert.equal(claims(bearer).aud, 'app:abc', 'the request carries a token minted for the audience');
  assert.match(direct.badHost, /not a host name/, 'a URL is not a host: ' + direct.badHost);
  assert.deepEqual(direct.states, ['signed-out'], 'signing out closes the channel');
  assert.equal(direct.after, 'signed-out');

  // ── Sealed: no approval yet ──
  const sealed = await page.evaluate(async () => {
    const auth = new Privasys.AuthFrame({ authOrigin: 'https://idp.test', clientId: 'wallet-site', appName: 'Wallet Site' });
    window.sealed = auth;
    await auth.connect();
    const approvals = [];
    const error = await auth.app('enc.test', { onApproval: (r) => approvals.push(r) }).then(() => 'opened', (e) => e.message);
    return { approvals, error };
  });
  assert.ok(encauthCalls.length >= 1 && encauthCalls[0].host === 'enc.test', 'a wallet session resumes from the approval for the host');
  assert.match(encauthCalls[0].auth, /^Bearer /, 'the approval is fetched with the session\'s token');
  assert.deepEqual(sealed.approvals, [null], 'with no approval, onApproval(null) is called while the wallet is asked');
  assert.equal(notified.length, 1, 'the wallet is asked once');
  assert.equal(notified[0].mode, 'voucher-only', 'by a voucher-only push');
  assert.equal(notified[0].appHost, 'enc.test', 'for that host');
  assert.equal(notified[0].sid, 'sid-1', 'on the session\'s sign-in');
  assert.ok(bootstraps.includes('enc.test'), 'the approval is used to resume');
  assert.equal(sealed.error, 'unavailable', 'a host that cannot answer fails app(): ' + sealed.error);

  // ── Sealed: an approval the enclave refuses ──
  const refused = await page.evaluate(async () => {
    const approvals = [];
    const error = await window.sealed.app('enc2.test', { onApproval: (r) => approvals.push(r) }).then(() => 'opened', (e) => e.message);
    return { approvals, error };
  });
  assert.deepEqual(refused.approvals, ['enc-changed'], 'a refused approval names why: ' + JSON.stringify(refused.approvals));
  assert.equal(notified.at(-1).appHost, 'enc2.test', 'the wallet is asked for that host');
  assert.equal(refused.error, 'rejected:enc-changed', 'still refused after the new approval: ' + refused.error);

  // ── A wallet session that the app asks to reach directly ──
  const pushesBefore = notified.length;
  const forced = await page.evaluate(async () => {
    const ch = await window.sealed.app('app.test', { audience: 'app:abc', transport: 'direct' });
    const res = await ch.request('GET', '/ping');
    return { transport: ch.transport, status: res.status };
  });
  assert.equal(forced.transport, 'direct', 'transport: direct reaches the app over HTTPS for a wallet session');
  assert.equal(forced.status, 200);
  assert.equal(notified.length, pushesBefore, 'a direct channel asks the wallet for nothing');
  assert.equal(claims(appCalls.at(-1).auth.replace(/^Bearer /, '')).aud, 'app:abc', 'with a token for the audience');

  console.log('app-channel: all checks passed');
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
