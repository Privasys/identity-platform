// The hosted frame obeys only the page that embeds it. Another frame on the
// same page (an ad, a widget) can reach it through `parent.frames` and post
// to it; every command it sends must be ignored. The same commands from the
// embedding page still work.
// Run after `npm run build`: `node e2e/frame-security.cjs`.
// FRAME_BUNDLE=<path> runs it against another build of the frame.
const fs = require('fs');
const assert = require('assert/strict');
const { chromium } = require(process.cwd() + '/node_modules/playwright');

const frameBundle = fs.readFileSync(process.env.FRAME_BUNDLE || 'dist/privasys-auth-frame.iife.js', 'utf8');
const clientBundle = fs.readFileSync('dist/privasys-auth-client.iife.js', 'utf8');
const framePage = '<!doctype html><html><head><title>auth</title></head><body><script src="/auth/privasys-auth-frame.iife.js"></script></body></html>';
const sitePage = '<!doctype html><html><body><script src="/client.js"></script></body></html>';
const evilPage = '<!doctype html><html><body>widget</body></html>';

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (n) => `${b64({ alg: 'none' })}.${b64({ aud: 'privasys-platform', exp: Math.floor(Date.now() / 1000) + 900, n })}.x`;

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  let refreshes = 0;
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
        refreshes++;
        return r.fulfill({ contentType: 'application/json', body: JSON.stringify({
          access_token: jwt(refreshes), refresh_token: `rt-${refreshes}`, token_type: 'Bearer', expires_in: 900 }) });
      }
      return r.fulfill({ contentType: 'application/json', body: '{}' });
    }
    if (u.host === 'evil.test') return r.fulfill({ contentType: 'text/html', body: evilPage });
    if (u.host === 'site-a.test') {
      if (u.pathname === '/client.js') return r.fulfill({ contentType: 'text/javascript', body: clientBundle });
      return r.fulfill({ contentType: 'text/html', body: sitePage });
    }
    return r.fulfill({ status: 404, body: '' });
  });

  const page = await ctx.newPage();
  await page.goto('https://site-a.test/');

  // Seed the frame's storage with a signed-in session for client c1.
  await page.evaluate(() => new Promise((resolve) => {
    const f = document.createElement('iframe');
    f.src = 'https://idp.test/auth/';
    f.onload = () => resolve();
    document.body.append(f);
    window.__seed = f;
  }));
  const seedFrame = page.frames().find((f) => f.url().startsWith('https://idp.test/auth/'));
  await seedFrame.evaluate((t) => localStorage.setItem('privasys_sessions', JSON.stringify([
    { token: t, rpId: 'app', origin: 'https://site-a.test', authenticatedAt: Date.now(), clientId: 'c1', refreshToken: 'rt-0' },
  ])), jwt(0));
  await page.evaluate(() => window.__seed.remove());

  // The page's own frame, signed in; and a widget from another origin.
  await page.evaluate(async () => {
    window.auth = new Privasys.AuthFrame({ authOrigin: 'https://idp.test', clientId: 'c1', rpId: 'app', appName: 'app', apiBase: 'https://api.test' });
    window.restored = await window.auth.getSession();
    const w = document.createElement('iframe');
    w.src = 'https://evil.test/';
    await new Promise((r) => { w.onload = r; document.body.append(w); });
  });
  assert.ok(await page.evaluate(() => !!window.restored), 'the seeded session is restored');

  const idpFrame = page.frames().find((f) => f.url().startsWith('https://idp.test/auth/'));
  const evil = page.frames().find((f) => f.url().startsWith('https://evil.test/'));
  const stored = () => idpFrame.evaluate(() => JSON.parse(localStorage.getItem('privasys_sessions') || '[]').length);
  const gateDrawn = () => idpFrame.evaluate(() => !!document.querySelector('[data-privasys-auth]'));

  // The widget posts to every frame of the page; only the privasys.id frame
  // receives a message addressed to its origin. It also listens for any reply.
  const attack = async (msg) => {
    await evil.evaluate((m) => {
      window.replies = window.replies || [];
      if (!window.listening) {
        window.listening = true;
        addEventListener('message', (e) => window.replies.push(e.data && e.data.type));
      }
      for (let i = 0; i < parent.frames.length; i++) {
        if (parent.frames[i] !== window) parent.frames[i].postMessage(m, 'https://idp.test');
      }
    }, msg);
    await page.waitForTimeout(600);
  };

  const before = refreshes;
  await attack({ type: 'privasys:renew-session', id: 'x1', rpId: 'app', clientId: 'c1' });
  await attack({ type: 'privasys:get-token-for-audience', id: 'x2', rpId: 'app', clientId: 'c1', audience: 'app:abc' });
  assert.equal(refreshes, before, 'a widget made the frame spend the refresh token');

  await attack({ type: 'privasys:clear-session', rpId: 'app', clientId: 'c1' });
  assert.equal(await stored(), 1, 'a widget signed the person out');

  await attack({ type: 'privasys:init', config: { appName: 'Evil', clientId: 'c1', rpId: 'app', presentation: 'inline', methods: ['wallet'] } });
  assert.equal(await gateDrawn(), false, 'a widget drew a gate inside the privasys.id frame');

  await attack({ type: 'privasys:session:request', id: 'x3', method: 'POST', path: '/transfer', body: {} });
  await attack({ type: 'privasys:session:ws-send', id: 1, data: 'x' });
  await attack({ type: 'privasys:check-session', rpId: 'app', clientId: 'c1' });
  const replies = await evil.evaluate(() => window.replies);
  assert.deepEqual(replies, [], 'the frame answered a widget: ' + JSON.stringify(replies));

  // The embedding page still drives the frame.
  const token = await page.evaluate(() => window.auth.renewSession());
  assert.ok(token && refreshes === before + 1, 'the page itself can renew');
  await page.evaluate(() => window.auth.clearSession());
  assert.equal(await page.evaluate(() => window.auth.getSession()), null, 'the page itself can sign out');

  console.log('frame-security: all checks passed');
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
