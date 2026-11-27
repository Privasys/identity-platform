// An operation approval on the identity provider's own page: the frame polls
// the status address the page named and ends with the page's own words; it
// refuses a status or decline address on another origin, and an approval
// asked for from any other page. It runs through IdpGate.
// Run after `npm run build`: `node e2e/operation-approval.cjs`.
const fs = require('fs');
const assert = require('assert/strict');
const { chromium } = require(process.cwd() + '/node_modules/playwright');

const frameBundle = fs.readFileSync('dist/privasys-auth-frame.iife.js', 'utf8');
const clientBundle = fs.readFileSync('dist/privasys-auth-client.iife.js', 'utf8');
const framePage = '<!doctype html><html><head><title>auth</title></head><body><script src="/auth/v1/privasys-auth-frame.iife.js"></script></body></html>';
const sitePage = '<!doctype html><html><body><div id="gate"></div><script src="/client.js"></script></body></html>';

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  // Shadow roots open, so the test can read what the gate says.
  await ctx.addInitScript(() => {
    const attach = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function (init) { return attach.call(this, { ...init, mode: 'open' }); };
  });
  let status = 'pending';
  const polled = [];
  await ctx.route('https://**/*', async (r) => {
    const u = new URL(r.request().url());
    if (u.host === 'idp.test' || u.host === 'site-a.test') {
      if (u.pathname === '/auth/v1/') return r.fulfill({ contentType: 'text/html', body: framePage });
      if (u.pathname === '/auth/v1/privasys-auth-frame.iife.js') return r.fulfill({ contentType: 'text/javascript', body: frameBundle });
      if (u.pathname === '/client.js') return r.fulfill({ contentType: 'text/javascript', body: clientBundle });
      if (u.pathname === '/wallet/platforms') return r.fulfill({ contentType: 'application/json', body: '{"platforms":[{"audience":"privasys-platform"}]}' });
      if (u.pathname === '/op/status') {
        polled.push(u.search);
        return r.fulfill({ contentType: 'application/json', body: JSON.stringify({ status }) });
      }
      if (u.pathname === '/approve') return r.fulfill({ contentType: 'text/html', body: sitePage });
      return r.fulfill({ contentType: 'application/json', body: '{}' });
    }
    return r.fulfill({ status: 404, body: '' });
  });

  const run = async (origin, op) => {
    const page = await ctx.newPage();
    await page.goto(origin + '/approve');
    const out = await page.evaluate(async (op) => {
      const gate = new Privasys.IdpGate({
        authOrigin: 'https://idp.test', appName: 'Example',
        presentation: 'page', container: document.getElementById('gate'), operationApproval: op,
      });
      try { return { result: await gate.run() }; } catch (e) { return { error: e.message, code: e.code }; }
    }, op);
    const frame = page.frames().find((f) => f.url().startsWith('https://idp.test/auth/v1/'));
    const shown = frame ? await frame.evaluate(() => document.querySelector('[data-privasys-auth]')?.shadowRoot?.textContent ?? '') : '';
    await page.close();
    return { ...out, shown };
  };

  const op = {
    walletLink: 'privasys-wallet://approvals?op=abc123',
    statusUrl: '/op/status?op=abc123',
    declineUrl: '/op/decline?op=abc123',
    messages: { approved: 'The tool carries on by itself.' },
  };

  const foreign = await run('https://idp.test', { ...op, statusUrl: 'https://evil.test/op/status' });
  assert.equal(foreign.error, 'this approval cannot be shown on this page', 'a status address on another origin is refused');
  const foreignDecline = await run('https://idp.test', { ...op, declineUrl: 'https://evil.test/op/decline' });
  assert.equal(foreignDecline.error, 'this approval cannot be shown on this page', 'a decline address on another origin is refused');
  const otherPage = await run('https://site-a.test', op);
  assert.equal(otherPage.error, 'this approval cannot be shown on this page', 'another page cannot run an approval');

  setTimeout(() => { status = 'approved'; }, 1000);
  const approved = await run('https://idp.test', op);
  assert.equal(approved.result && approved.result.approved, true, 'the approval resolves once the status says so: ' + JSON.stringify(approved));
  assert.ok(polled.length > 0 && polled.every((q) => q === '?op=abc123'), 'the frame polls the address the page named');
  assert.match(approved.shown, /The tool carries on by itself\./, "the gate ends on the page's words");

  status = 'gone';
  const expired = await run('https://idp.test', op);
  assert.equal(expired.result && expired.result.outcome, 'approval-failed', 'an expired approval settles run()');
  assert.match(expired.shown, /This approval has expired\./, 'the gate says it expired');

  console.log('operation-approval: all checks passed');
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
