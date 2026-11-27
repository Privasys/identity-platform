// The gate's outcomes settle IdpGate.run(): declining an operation from the
// gate, a decline that cannot be recorded, and an approval that fails each
// resolve with `approved: false` and their outcome, while the gate stays on
// screen to say so. Run after `npm run build`: `node e2e/gate-outcomes.cjs`.
const fs = require('fs');
const assert = require('assert/strict');
const { chromium } = require(process.cwd() + '/node_modules/playwright');

const frameBundle = fs.readFileSync('dist/privasys-auth-frame.iife.js', 'utf8');
const clientBundle = fs.readFileSync('dist/privasys-auth-client.iife.js', 'utf8');
const framePage = '<!doctype html><html><head><title>auth</title></head><body><script src="/auth/v1/privasys-auth-frame.iife.js"></script></body></html>';
const sitePage = '<!doctype html><html><body><div id="gate" style="height:640px"></div><script src="/client.js"></script></body></html>';

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  await ctx.addInitScript(() => {
    const attach = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function (init) { return attach.call(this, { ...init, mode: 'open' }); };
  });
  let status = 'pending';
  let declineStatus = 204;
  await ctx.route('https://**/*', async (r) => {
    const u = new URL(r.request().url());
    if (u.host !== 'idp.test') return r.fulfill({ status: 404, body: '' });
    if (u.pathname === '/auth/v1/') return r.fulfill({ contentType: 'text/html', body: framePage });
    if (u.pathname === '/auth/v1/privasys-auth-frame.iife.js') return r.fulfill({ contentType: 'text/javascript', body: frameBundle });
    if (u.pathname === '/client.js') return r.fulfill({ contentType: 'text/javascript', body: clientBundle });
    if (u.pathname === '/wallet/platforms') return r.fulfill({ contentType: 'application/json', body: '{"platforms":[{"audience":"privasys-platform"}]}' });
    if (u.pathname === '/op/status') return r.fulfill({ contentType: 'application/json', body: JSON.stringify({ status }) });
    if (u.pathname === '/op/decline') return r.fulfill({ status: declineStatus, body: '' });
    if (u.pathname === '/approve') return r.fulfill({ contentType: 'text/html', body: sitePage });
    return r.fulfill({ contentType: 'application/json', body: '{}' });
  });

  // Opens an operation approval through IdpGate, declines it from the gate
  // unless the approval fails by itself, and returns how run() settled.
  const run = async ({ decline }) => {
    const page = await ctx.newPage();
    await page.goto('https://idp.test/approve');
    await page.evaluate(() => {
      window.settled = null;
      new Privasys.IdpGate({
        appName: 'Example', presentation: 'page', container: document.getElementById('gate'),
        operationApproval: {
          walletLink: 'privasys-wallet://approvals?op=x',
          statusUrl: '/op/status?op=x',
          declineUrl: '/op/decline?op=x',
          messages: { declined: 'You declined this request.' },
        },
      }).run().then((r) => { window.settled = r; }, (e) => { window.settled = { error: e.message }; });
    });
    const frame = page.frameLocator('#gate iframe');
    if (decline) await frame.locator('[data-privasys-auth]').getByRole('button', { name: /decline/i }).click();
    await page.waitForFunction(() => window.settled !== null, null, { timeout: 10000 }).catch(() => undefined);
    const settled = await page.evaluate(() => window.settled);
    const f = page.frames().find((x) => x.url().startsWith('https://idp.test/auth/v1/'));
    const shown = f ? await f.evaluate(() => document.querySelector('[data-privasys-auth]')?.shadowRoot?.textContent ?? '') : '';
    await page.close();
    return { settled, shown };
  };

  const declined = await run({ decline: true });
  assert.deepEqual(declined.settled, { approved: false, outcome: 'declined' }, 'a decline from the gate settles run(): ' + JSON.stringify(declined.settled));
  assert.match(declined.shown, /You declined this request/, 'the gate stays on the decline');

  declineStatus = 409;
  const notRecorded = await run({ decline: true });
  assert.deepEqual(notRecorded.settled, { approved: false, outcome: 'decline-failed' }, 'a decline that cannot be recorded settles run()');
  assert.match(notRecorded.shown, /Could not decline/, 'the gate says the decline was not recorded');

  status = 'gone';
  const failed = await run({ decline: false });
  assert.deepEqual(failed.settled, { approved: false, outcome: 'approval-failed' }, 'a failed approval settles run()');
  assert.match(failed.shown, /expired/, 'the gate says why the approval failed');

  console.log('gate-outcomes: all checks passed');
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
