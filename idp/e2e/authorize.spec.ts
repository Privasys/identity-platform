import { test, expect } from "@playwright/test";
import { createHash, randomBytes } from "crypto";

/**
 * Generate a PKCE code_verifier / code_challenge pair.
 */
function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

const CLIENT_ID = "cd0d8398230db7f8f8f047eff2cf8946";
const REDIRECT_URI = "https://auth.privasys.org/idps/callback";

/**
 * Build a valid /authorize URL with all required OIDC params.
 */
function authorizeURL(base: string, codeChallenge: string) {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid profile email",
    state: randomBytes(16).toString("hex"),
    nonce: randomBytes(16).toString("hex"),
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
  return `${base}/authorize?${params}`;
}

test.describe("/authorize page", () => {
  test("renders the QR code and page elements correctly", async ({ page, baseURL }) => {
    const { challenge } = pkce();
    const url = authorizeURL(baseURL!, challenge);

    await page.goto(url);

    // Page title
    await expect(page).toHaveTitle("Sign in with Privasys ID");

    // Heading
    await expect(page.locator("h1")).toHaveText("Sign in with Privasys ID");

    // Subtitle
    await expect(page.locator(".subtitle")).toHaveText(
      "Scan the QR code with your Privasys Wallet"
    );

    // QR code image should be visible and loaded (not broken)
    const qrImg = page.locator(".qr-frame img");
    await expect(qrImg).toBeVisible();

    // Verify the image actually loaded (naturalWidth > 0)
    const naturalWidth = await qrImg.evaluate(
      (img: HTMLImageElement) => img.naturalWidth
    );
    expect(naturalWidth).toBeGreaterThan(0);

    // Verify it's a data URI
    const src = await qrImg.getAttribute("src");
    expect(src).toMatch(/^data:image\/png;base64,/);

    // Status text
    await expect(page.locator("#status")).toHaveText("Waiting for wallet…");

    // Timer should show a countdown
    await expect(page.locator("#timer")).toContainText("Expires in");

    // Mobile deep link (hidden on desktop but present in DOM)
    const walletLink = page.locator(".wallet-btn a");
    await expect(walletLink).toHaveAttribute("href", /^https:\/\/privasys\.id\/scp\?p=/);
  });

  test("QR payload matches SDK format", async ({ page, baseURL }) => {
    const { challenge } = pkce();
    await page.goto(authorizeURL(baseURL!, challenge));

    // Extract the universal link from the wallet button
    const href = await page.locator(".wallet-btn a").getAttribute("href");
    expect(href).toBeTruthy();

    // Decode the payload: https://privasys.id/scp?p=<base64url>
    const url = new URL(href!);
    const b64 = url.searchParams.get("p")!;
    // Decode base64url (Node atob works with standard base64)
    const json = Buffer.from(b64, "base64url").toString("utf-8");
    const payload = JSON.parse(json);

    // Verify structure matches SDK's QRPayload interface
    expect(payload).toHaveProperty("origin", "privasys.id");
    expect(payload).toHaveProperty("rpId", "privasys.id");
    expect(payload).toHaveProperty("brokerUrl", "wss://broker.privasys.org/relay");
    expect(payload).toHaveProperty("sessionId");
    expect(typeof payload.sessionId).toBe("string");
    expect(payload.sessionId.length).toBeGreaterThan(0);

    // Must NOT have unexpected fields (the wallet may choke on them)
    const expectedKeys = ["origin", "sessionId", "rpId", "brokerUrl"];
    expect(Object.keys(payload).sort()).toEqual(expectedKeys.sort());
  });

  test("countdown timer decrements", async ({ page, baseURL }) => {
    const { challenge } = pkce();
    await page.goto(authorizeURL(baseURL!, challenge));

    const timerEl = page.locator("#timer");
    const firstText = await timerEl.textContent();
    expect(firstText).toContainEqual; // sanity

    // Wait 2 seconds and verify the timer changed
    await page.waitForTimeout(2500);
    const secondText = await timerEl.textContent();
    expect(secondText).not.toBe(firstText);
  });

  test("polls /session/status endpoint", async ({ page, baseURL }) => {
    const { challenge } = pkce();

    // Intercept poll requests to verify they happen
    const pollRequests: string[] = [];
    await page.route("**/session/status*", async (route) => {
      pollRequests.push(route.request().url());
      // Return unauthenticated to keep polling
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ authenticated: false }),
      });
    });

    await page.goto(authorizeURL(baseURL!, challenge));

    // Wait enough time for at least one poll (polls every 2s)
    await page.waitForTimeout(3000);
    expect(pollRequests.length).toBeGreaterThanOrEqual(1);

    // Verify poll URL contains session_id
    expect(pollRequests[0]).toContain("session_id=");
  });

  test("redirects when session is authenticated", async ({ page, baseURL }) => {
    const { challenge } = pkce();

    // Intercept poll requests and return authenticated on first call
    await page.route("**/session/status*", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          authenticated: true,
          redirect_uri: `${REDIRECT_URI}?code=test_code&state=test_state`,
        }),
      });
    });

    await page.goto(authorizeURL(baseURL!, challenge));

    // The page JS should redirect to the callback URL after the first poll
    await page.waitForURL(`${REDIRECT_URI}**`, { timeout: 10_000 });
    expect(page.url()).toContain("code=test_code");
    expect(page.url()).toContain("state=test_state");
  });

  test("no console errors on page load", async ({ page, baseURL }) => {
    const errors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") errors.push(msg.text());
    });

    const { challenge } = pkce();
    await page.goto(authorizeURL(baseURL!, challenge));

    // Give the page a moment to initialize
    await page.waitForTimeout(1000);
    expect(errors).toEqual([]);
  });
});
