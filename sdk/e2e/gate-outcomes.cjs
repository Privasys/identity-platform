// The gate's outcomes settle the caller: declining an operation from the
// gate, a decline that cannot be recorded, and an approval that fails each
// end signIn() with their code, while the gate stays on screen to say so.
// Run after `npm run build`: `node e2e/gate-outcomes.cjs`.
const fs = require('fs');
const assert = require('assert/strict');
const { chromium } = require(process.cwd() + '/node_modules/playwright');

const bundle = fs.readFileSync('dist/privasys-auth.iife.js', 'utf8');

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  await ctx.addInitScript(() => {
    const attach = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function (init) { return attach.call(this, { ...init, mode: 'open' }); };
  });
  await ctx.route('https://gate.test/', (r) => r.fulfill({ contentType: 'text/html', body: '<!doctype html><html><body></body></html>' }));

  // Opens an operation approval gate and returns how signIn() settled,
  // after `act` ran in the page.
  const run = async ({ declineFails, approvalFails }) => {
    const page = await ctx.newPage();
    await page.goto('https://gate.test/');
    await page.addScriptTag({ content: bundle });
    await page.evaluate(({ declineFails, approvalFails }) => {
      window.settled = null;
      new Privasys.AuthUI({
        apiBase: 'https://gate.test', appName: 'Example', rpId: 'gate.test', presentation: 'page',
        operationApproval: {
          walletLink: 'privasys-wallet://vault-approvals?vault_op=x',
          wait: () => approvalFails ? Promise.reject(new Error('This approval expired.')) : new Promise(() => {}),
        },
        decline: {
          label: 'Not me, decline', title: 'Declined', message: 'You declined this request.',
          run: () => declineFails ? Promise.reject(new Error('already answered')) : Promise.resolve(),
        },
      }).signIn().then(() => { window.settled = 'resolved'; }, (e) => { window.settled = e.message; });
    }, { declineFails, approvalFails });
    if (!approvalFails) await page.locator('[data-privasys-auth]').getByRole('button', { name: /decline/i }).click();
    await page.waitForFunction(() => window.settled !== null, null, { timeout: 5000 }).catch(() => undefined);
    const settled = await page.evaluate(() => window.settled);
    const shown = await page.evaluate(() => document.querySelector('[data-privasys-auth]')?.shadowRoot?.textContent ?? '');
    await page.close();
    return { settled, shown };
  };

  const declined = await run({});
  assert.equal(declined.settled, 'declined', 'a decline from the gate settles signIn()');
  assert.match(declined.shown, /You declined this request/, 'the gate stays on the decline');

  const notRecorded = await run({ declineFails: true });
  assert.equal(notRecorded.settled, 'decline-failed', 'a decline that cannot be recorded settles signIn()');
  assert.match(notRecorded.shown, /Could not decline/, 'the gate says the decline was not recorded');

  const failed = await run({ approvalFails: true });
  assert.equal(failed.settled, 'approval-failed', 'a failed approval settles signIn()');
  assert.match(failed.shown, /expired/, 'the gate says why the approval failed');

  console.log('gate-outcomes: all checks passed');
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
