// Two tabs of one site share the person's session, and each hears of every
// change made in another: a renewal, a sign-out, and a sign-in reaching a tab
// that is signed out.
// Run after `npm run build`: `node e2e/multi-tab.cjs`.
const fs = require('fs');
const assert = require('assert/strict');
const { chromium } = require(process.cwd() + '/node_modules/playwright');

const frameBundle = fs.readFileSync('dist/privasys-auth-frame.iife.js', 'utf8');
const clientBundle = fs.readFileSync('dist/privasys-auth-client.iife.js', 'utf8');
const framePage = '<!doctype html><html><head><title>auth</title></head><body><script src="/auth/v1/privasys-auth-frame.iife.js"></script></body></html>';
const sitePage = '<!doctype html><html><body><script src="/client.js"></script></body></html>';

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (n) => `${b64({ alg: 'none' })}.${b64({ aud: 'privasys-platform', exp: Math.floor(Date.now() / 1000) + 900, n })}.x`;
const n = (t) => (t ? JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()).n : null);

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  let refreshes = 0;
  await ctx.route('https://**/*', async (r) => {
    const u = new URL(r.request().url());
    if (u.host === 'idp.test') {
      if (u.pathname === '/auth/v1/') return r.fulfill({ contentType: 'text/html', body: framePage });
      if (u.pathname === '/auth/v1/privasys-auth-frame.iife.js') return r.fulfill({ contentType: 'text/javascript', body: frameBundle });
      if (u.pathname === '/wallet/platforms') return r.fulfill({ contentType: 'application/json', body: '{"platforms":[{"audience":"privasys-platform"}]}' });
      if (u.pathname === '/session/client-origin') return r.fulfill({ contentType: 'application/json', body: '{"allowed":true}' });
      if (u.pathname === '/token') {
        refreshes++;
        return r.fulfill({ contentType: 'application/json', body: JSON.stringify({
          access_token: jwt(refreshes), refresh_token: `rt-${refreshes}`, token_type: 'Bearer', expires_in: 900 }) });
      }
      return r.fulfill({ contentType: 'application/json', body: '{}' });
    }
    if (u.host === 'site-a.test') {
      if (u.pathname === '/client.js') return r.fulfill({ contentType: 'text/javascript', body: clientBundle });
      return r.fulfill({ contentType: 'text/html', body: sitePage });
    }
    return r.fulfill({ status: 404, body: '' });
  });

  const session = (t) => [{ token: t, rpId: 'privasys.id', authenticatedAt: Date.now(), clientId: 'c1', refreshToken: 'rt-0', scope: 'openid offline_access', platform: 'privasys-platform' }];
  // Writes the frame's storage from a frame of its own, as a sign-in in
  // another tab does.
  const seed = async (page, value) => {
    await page.evaluate(() => new Promise((resolve) => {
      const f = document.createElement('iframe');
      f.src = 'https://idp.test/auth/v1/?seed';
      f.onload = () => resolve();
      document.body.append(f);
      window.__seed = f;
    }));
    const f = page.frames().find((x) => x.url() === 'https://idp.test/auth/v1/?seed');
    await f.evaluate((v) => v ? localStorage.setItem('privasys_sessions', JSON.stringify(v)) : localStorage.removeItem('privasys_sessions'), value);
    await page.evaluate(() => window.__seed.remove());
  };
  const open = async () => {
    const p = await ctx.newPage();
    await p.goto('https://site-a.test/');
    return p;
  };
  // Mounts the page's AuthFrame and waits for the frame's first report.
  const mount = (p) => p.evaluate(() => new Promise((resolve) => {
    window.events = [];
    window.auth = new Privasys.AuthFrame({ authOrigin: 'https://idp.test', clientId: 'c1', appName: 'app' });
    let first = true;
    window.auth.onSessionChange((s) => {
      window.events.push(s ? s.token : null);
      if (first) { first = false; resolve(s && s.token); }
    });
  }));
  const heard = (p, pred, label) => p.waitForFunction(pred, null, { timeout: 5000 })
    .catch(() => { throw new Error(`not heard: ${label}`); });

  const a = await open();
  await seed(a, session(jwt(0)));
  const b = await open();
  assert.equal(n(await mount(a)), 0, 'tab A restores the session');
  assert.equal(n(await mount(b)), 0, 'tab B restores the session');

  // A renewal in tab A reaches tab B.
  const renewed = await a.evaluate(() => window.auth.renew().then((s) => s.token));
  await b.waitForFunction((t) => window.auth.session && window.auth.session.token === t, renewed, { timeout: 5000 });
  assert.equal(await b.evaluate(() => window.events.at(-1)), renewed, 'tab B gets the token tab A renewed');

  // Signing out in tab A: tab B hears of it.
  await a.evaluate(() => window.auth.signOut());
  await heard(b, () => window.events.at(-1) === null && window.auth.session === null, 'sign-out in another tab');

  // Signing in from tab A while tab C is signed out: tab C hears of it.
  const c = await open();
  assert.equal(await mount(c), null, 'a new tab after the sign-out has no session');
  await seed(a, session(jwt(99)));
  await heard(c, () => window.auth.session !== null, 'sign-in in another tab');
  assert.equal(n(await c.evaluate(() => window.auth.session.token)), 99, 'tab C has the new session');
  assert.equal(n(await b.evaluate(() => window.events.at(-1))), 99, 'tab B, signed out, hears of it too');

  console.log('multi-tab: all checks passed');
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
