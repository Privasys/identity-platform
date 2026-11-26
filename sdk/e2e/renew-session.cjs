// AuthFrame.renewSession(), end to end against a mocked identity provider:
// a page renews a session that is not due, gets the new token, sees it in
// onSessionRenewed and getSession(); two calls at once make one refresh; a
// call within 10 s makes none; a message for no client or another client
// renews nothing; a page with no session is refused. Run after `npm run build`:
// `node e2e/renew-session.cjs`.
const fs = require('fs');
const assert = require('assert/strict');
const { chromium } = require(process.cwd() + '/node_modules/playwright');

const frameBundle = fs.readFileSync('dist/privasys-auth-frame.iife.js', 'utf8');
const clientBundle = fs.readFileSync('dist/privasys-auth-client.iife.js', 'utf8');
const framePage = '<!doctype html><html><head><title>auth</title></head><body><script src="/auth/privasys-auth-frame.iife.js"></script></body></html>';
const sitePage = '<!doctype html><html><body><script src="/client.js"></script></body></html>';

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (n) => `${b64({ alg: 'none' })}.${b64({ aud: 'privasys-platform', exp: Math.floor(Date.now() / 1000) + 900, n })}.x`;

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  let refreshes = 0;
  const usedRefreshTokens = [];
  await ctx.route('https://**/*', async (r) => {
    const u = new URL(r.request().url());
    if (u.host === 'idp.test') {
      if (u.pathname === '/auth/') return r.fulfill({ contentType: 'text/html', body: framePage });
      if (u.pathname === '/auth/privasys-auth-frame.iife.js') return r.fulfill({ contentType: 'text/javascript', body: frameBundle });
      if (u.pathname === '/wallet/platforms') return r.fulfill({ contentType: 'application/json', body: '{"platforms":[{"audience":"privasys-platform"}]}' });
      if (u.pathname === '/session/client-origin') {
        return r.fulfill({ contentType: 'application/json', body: JSON.stringify({ allowed: u.searchParams.get('origin') === 'https://site-a.test' }) });
      }
      if (u.pathname === '/token') {
        const form = new URLSearchParams(r.request().postData() || '');
        usedRefreshTokens.push(form.get('refresh_token'));
        refreshes++;
        await new Promise((res) => setTimeout(res, 300));
        return r.fulfill({ contentType: 'application/json', body: JSON.stringify({
          access_token: jwt(refreshes), refresh_token: `rt-${refreshes}`, token_type: 'Bearer', expires_in: 900 }) });
      }
      return r.fulfill({ contentType: 'application/json', body: '{}' });
    }
    if (u.host.startsWith('site-')) {
      if (u.pathname === '/client.js') return r.fulfill({ contentType: 'text/javascript', body: clientBundle });
      return r.fulfill({ contentType: 'text/html', body: sitePage });
    }
    return r.fulfill({ status: 404, body: '' });
  });

  // Seed the frame's storage (partitioned under site-a) with a session that is not due.
  const page = await ctx.newPage();
  await page.goto('https://site-a.test/');
  const seed = [{ token: jwt(0), rpId: 'app', origin: 'https://site-a.test', authenticatedAt: Date.now(), clientId: 'c1', refreshToken: 'rt-0' }];
  await page.evaluate((s) => new Promise((resolve) => {
    const f = document.createElement('iframe');
    f.src = 'https://idp.test/auth/';
    f.onload = () => resolve();
    document.body.append(f);
    window.__seedFrame = f;
  }), null);
  const idpFrame = page.frames().find((f) => f.url().startsWith('https://idp.test/auth/'));
  await idpFrame.evaluate((s) => localStorage.setItem('privasys_sessions', JSON.stringify(s)), seed);
  await page.evaluate(() => window.__seedFrame.remove());

  const out = await page.evaluate(async () => {
    const auth = new Privasys.AuthFrame({ authOrigin: 'https://idp.test', clientId: 'c1', rpId: 'app', appName: 'app', apiBase: 'https://api.test' });
    const renewed = [];
    auth.onSessionRenewed = (rpId, tok) => renewed.push(tok);
    const before = await auth.getSession();
    const [a, b] = await Promise.all([auth.renewSession(), auth.renewSession()]);
    const after = await auth.getSession();
    // Within 10 s of the last renewal: the current token, and no refresh.
    const soon = await auth.renewSession();
    // A message naming no client, or another client, renews nothing.
    const raw = (msg) => new Promise((resolve) => {
      const win = auth.sessionIframe.contentWindow;
      const id = 'raw-' + Math.random();
      addEventListener('message', function h(e) {
        if (e.source === win && e.data && e.data.type === 'privasys:renew-session:response' && e.data.id === id) {
          removeEventListener('message', h);
          resolve(e.data.error || 'renewed');
        }
      });
      win.postMessage({ type: 'privasys:renew-session', id, rpId: 'app', ...msg }, 'https://idp.test');
    });
    const noClient = await raw({});
    const otherClient = await raw({ clientId: 'c2' });
    await new Promise((r) => setTimeout(r, 10_500));
    const third = await auth.renewSession();
    return { before: before && before.token, a, b, after: after && after.token, soon, noClient, otherClient, third, renewed };
  });
  const n = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()).n;

  assert.equal(n(out.before), 0, 'the seeded session is restored');
  assert.equal(n(out.a), 1, 'renewSession returns the renewed token');
  assert.equal(out.a, out.b, 'two calls at once share one renewal');
  assert.equal(out.after, out.a, 'getSession gives the renewed token');
  assert.equal(out.soon, out.a, 'a call within 10 s returns the current token');
  assert.equal(out.noClient, 'no session to renew', 'a message naming no client is refused');
  assert.equal(out.otherClient, 'no session to renew', "another client's message is refused");
  assert.equal(n(out.third), 2, 'a call after 10 s renews again');
  assert.deepEqual(usedRefreshTokens, ['rt-0', 'rt-1'], 'each refresh token is spent once, in order');
  assert.ok(out.renewed.includes(out.a) && out.renewed.includes(out.third), 'onSessionRenewed carries each new token');

  // Another site, which the client does not accept, gets no session to renew.
  const other = await ctx.newPage();
  await other.goto('https://site-b.test/');
  const refused = await other.evaluate(async () => {
    const auth = new Privasys.AuthFrame({ authOrigin: 'https://idp.test', clientId: 'c1', rpId: 'app', appName: 'app', apiBase: 'https://api.test' });
    try { await auth.renewSession(); return 'renewed'; } catch (e) { return e.message; }
  });
  assert.equal(refused, 'no active session', 'a page with no session is refused');
  assert.equal(refreshes, 2, 'the refused page made no refresh');

  console.log('renew-session: all checks passed');
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
