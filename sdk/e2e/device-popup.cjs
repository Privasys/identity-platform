// The device popup, end to end, with the browser's storage partitioning left
// on. Playwright switches it off by default, which hides the very thing this
// checks: a frame embedded on a new site starts with an empty storage, and a
// popup on the identity provider's origin finds the phone the browser knows.
// Run after `npm run build`: `npm run test:popup`.
const fs = require('fs');
const { chromium } = require(process.cwd() + '/node_modules/playwright');

function disableArg() {
  const src = fs.readFileSync(process.cwd() + '/node_modules/playwright-core/lib/coreBundle.js', 'utf8');
  const block = src.slice(src.indexOf('disabledFeatures = ['), src.indexOf('];', src.indexOf('disabledFeatures = [')));
  return `--disable-features=${[...block.matchAll(/^\s*"([A-Za-z0-9]+)",?/gm)].map((m) => m[1]).join(',')}`;
}

const frameBundle = fs.readFileSync('dist/privasys-auth-frame.iife.js', 'utf8');
const framePage = '<!doctype html><html><head><title>auth</title></head><body><script src="/auth/privasys-auth-frame.iife.js"></script></body></html>';
// The embedding site: creates the frame and sends it the gate's init, as the client script does.
const sitePage = `<!doctype html><html><body><div id="c" style="width:420px;height:640px"></div><script>
  const f = document.createElement('iframe');
  f.src = 'https://idp.test/auth/'; f.style.cssText = 'width:420px;height:640px;border:0';
  addEventListener('message', (e) => {
    if (e.origin !== 'https://idp.test') return;
    if (e.data.type === 'privasys:ready') f.contentWindow.postMessage({ type: 'privasys:init', config: {
      apiBase: 'https://api.test', appName: 'example', clientId: 'c1', presentation: 'inline', methods: ['wallet', 'passkey'],
      brokerUrl: 'wss://broker.test/relay' } }, 'https://idp.test');
  });
  document.getElementById('c').append(f);
</script></body></html>`;

(async () => {
  const browser = await chromium.launch({ ignoreDefaultArgs: [disableArg()] });
  const ctx = await browser.newContext();
  await ctx.addInitScript(() => {
    const attach = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function (init) { return attach.call(this, { ...init, mode: 'open' }); };
  });
  await ctx.route('https://**/*', (r) => {
    const u = new URL(r.request().url());
    if (u.host === 'idp.test') {
      if (u.pathname === '/auth/') return r.fulfill({ contentType: 'text/html', body: framePage });
      if (u.pathname === '/auth/privasys-auth-frame.iife.js') return r.fulfill({ contentType: 'text/javascript', body: frameBundle });
      if (u.pathname === '/authorize') return r.fulfill({ contentType: 'application/json', body: JSON.stringify({
        session_id: 'sess1', poll_url: 'https://idp.test/session/status?session_id=sess1',
        qr_payload: 'https://idp.test/qr?p=abc', requested_attributes: [] }) });
      if (u.pathname === '/auth/social/providers') return r.fulfill({ contentType: 'application/json', body: '{"providers":[]}' });
      return r.fulfill({ contentType: 'application/json', body: '{}' });
    }
    if (u.host.startsWith('site-')) return r.fulfill({ contentType: 'text/html', body: sitePage });
    return r.fulfill({ status: 404, body: '' });
  });

  const gateText = async (page) => {
    const frame = page.frames().find((f) => f.url().startsWith('https://idp.test/auth/'));
    return frame.evaluate(() => {
      const r = document.querySelector('[data-privasys-auth]')?.shadowRoot;
      if (!r) return '';
      return [...r.children].filter((c) => c.tagName !== 'STYLE').map((c) => c.textContent).join(' ').replace(/\s+/g, ' ').trim();
    });
  };
  const clickWallet = async (page) => {
    const frame = page.frameLocator('iframe');
    await frame.getByRole('button', { name: /Privasys ID/i }).first().click();
  };
  const hintAtTopLevel = async () => {
    const p = await ctx.newPage();
    await p.goto('https://idp.test/auth/');
    const v = await p.evaluate(() => localStorage.getItem('privasys_device_hints'));
    await p.close();
    return v;
  };
  let failures = 0;
  const check = (name, ok, detail) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  [' + detail + ']' : ''}`); if (!ok) failures++; };

  // 1. Nothing remembered: the click opens the popup, finds nothing, and the QR code shows.
  let page = await ctx.newPage();
  await page.goto('https://site-a.test/');
  await page.waitForTimeout(1500);
  let popup = ctx.waitForEvent('page', { timeout: 6000 }).catch(() => null);
  await clickWallet(page);
  let pop = await popup;
  check('the click opens a popup on the identity provider', !!pop && pop.url() === 'https://idp.test/auth/#device', pop && pop.url());
  await page.waitForTimeout(2500);
  let text = await gateText(page);
  check('with nothing remembered the gate shows the QR code', (/QR code/i.test(text) || /WebSocket connection failed/.test(text)) && !/notification/i.test(text), text.slice(0, 140));
  check('the popup closed itself', !pop || pop.isClosed());
  await page.close();

  // 2. Store through the popup, as "Trust this device" does: an identity-provider window asks it to.
  const opener = await ctx.newPage();
  await opener.goto('https://idp.test/auth/');
  await opener.evaluate(() => new Promise((resolve) => {
    addEventListener('message', (e) => {
      if (e.origin !== location.origin) return;
      if (e.data.type === 'privasys:device:hello') e.source.postMessage({ type: 'privasys:device:ask', id: 'x1', op: 'store', pushToken: 'ExponentPushToken[abc]', brokerUrl: 'wss://broker.test/relay' }, location.origin);
      if (e.data.type === 'privasys:device:answer' && e.data.id === 'x1') resolve(true);
    });
    window.open('/auth/#device', 'privasys-device', 'width=420,height=240');
  }));
  await opener.close();
  const stored = await hintAtTopLevel();
  check("the popup stores the phone in the identity provider's own storage", !!stored && stored.includes('ExponentPushToken[abc]'), stored);

  // 3. A site never visited before: the click finds the phone and the gate sends the notification.
  page = await ctx.newPage();
  await page.goto('https://site-b.test/');
  await page.waitForTimeout(1500);
  const inFrame = await page.frames().find((f) => f.url().startsWith('https://idp.test/auth/')).evaluate(() => localStorage.getItem('privasys_device_hints'));
  check("the frame's own copy on the new site is empty", inFrame === null, String(inFrame));
  popup = ctx.waitForEvent('page', { timeout: 6000 }).catch(() => null);
  await clickWallet(page);
  pop = await popup;
  await page.waitForTimeout(2500);
  text = await gateText(page);
  check('on a new site the gate goes to the notification, not the QR code', /notification|check your phone/i.test(text) && !/QR code/i.test(text), text.slice(0, 140));
  check('the popup closed itself', !pop || pop.isClosed());
  await page.close();

  // 3b. A second wallet, with a name: a new site offers the choice.
  const askPopup = async (ask) => {
    const o = await ctx.newPage();
    await o.goto('https://idp.test/auth/');
    await o.evaluate((ask) => new Promise((resolve) => {
      addEventListener('message', (e) => {
        if (e.origin !== location.origin) return;
        if (e.data.type === 'privasys:device:hello') e.source.postMessage({ type: 'privasys:device:ask', id: 'x2', ...ask }, location.origin);
        if (e.data.type === 'privasys:device:answer' && e.data.id === 'x2') resolve(true);
      });
      window.open('/auth/#device', 'privasys-device', 'width=420,height=240');
    }), ask);
    await o.close();
  };
  await askPopup({ op: 'store', pushToken: 'ExponentPushToken[work]', brokerUrl: 'wss://broker.test/relay', label: 'Work phone' });
  page = await ctx.newPage();
  await page.goto('https://site-d.test/');
  await page.waitForTimeout(1500);
  await clickWallet(page);
  await page.waitForTimeout(2500);
  text = await gateText(page);
  check('with two wallets remembered a new site shows the choice', /Work phone/.test(text) && /Phone added/.test(text) && /Use another Privasys ID/.test(text), text.slice(0, 160));
  if (process.env.SHOT) await page.screenshot({ path: process.env.SHOT });
  const gate = page.frameLocator('iframe');
  await gate.getByRole('button', { name: /Phone added/ }).click();
  await page.waitForTimeout(2000);
  text = await gateText(page);
  check('choosing a wallet sends its notification', /Push notification failed|notification|check your phone/i.test(text) && !/Use another Privasys ID/.test(text), text.slice(0, 120));
  await page.close();

  // 3c. "Forget" removes a wallet here and from the identity provider's own storage.
  page = await ctx.newPage();
  await page.goto('https://site-e.test/');
  await page.waitForTimeout(1500);
  await clickWallet(page);
  await page.waitForTimeout(2500);
  await page.frameLocator('iframe').getByRole('button', { name: 'Forget' }).first().click();
  await page.waitForTimeout(2500);
  const left = JSON.parse((await hintAtTopLevel()) || '[]');
  check('"Forget" removes that wallet for every site', left.length === 1 && left[0].pushToken === 'ExponentPushToken[abc]', JSON.stringify(left.map((d) => d.pushToken)));
  text = await gateText(page);
  check('with one wallet left the gate shows its single button again', !/Use another Privasys ID/.test(text), text.slice(0, 120));
  await page.close();

  // 4. A page of another origin cannot use the popup: it gets no answer.
  page = await ctx.newPage();
  await page.goto('https://site-c.test/');
  const leaked = await page.evaluate(() => new Promise((resolve) => {
    let got = null;
    addEventListener('message', (e) => { if (String(e.data?.type || '').startsWith('privasys:device')) got = e.data; });
    const w = window.open('https://idp.test/auth/#device', 'd', 'width=420,height=240');
    setTimeout(() => { try { w && w.postMessage({ type: 'privasys:device:ask', id: 'evil', op: 'read' }, '*'); } catch {} }, 800);
    setTimeout(() => resolve(got), 2500);
  }));
  check('a page of another origin gets nothing from the popup', leaked === null, JSON.stringify(leaked));

  await browser.close();
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
