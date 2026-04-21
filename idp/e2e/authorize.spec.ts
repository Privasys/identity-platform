// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { test, expect } from "@playwright/test";
import { createHash, randomBytes } from "crypto";

function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

const CLIENT_ID = process.env.E2E_CLIENT_ID ?? "privasys-platform";
const REDIRECT_URI = process.env.E2E_REDIRECT_URI ?? "https://privasys.id/auth/callback";

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

test.describe("/authorize JSON endpoint", () => {
  test("returns session JSON with valid PKCE", async ({ request, baseURL }) => {
    const { challenge } = pkce();
    const resp = await request.get(authorizeURL(baseURL!, challenge), {
      headers: { Accept: "application/json" },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(typeof body.session_id).toBe("string");
    expect(body.session_id.length).toBeGreaterThan(0);
    expect(typeof body.qr_payload).toBe("string");
    expect(body.qr_payload).toMatch(/^https:\/\/privasys\.id\/scp\?p=/);
    expect(typeof body.poll_url).toBe("string");
    expect(body.poll_url).toContain("/session/status?session_id=");
    expect(body.expires_in).toBeGreaterThan(0);
  });

  test("QR payload decodes to expected SDK shape", async ({ request, baseURL }) => {
    const { challenge } = pkce();
    const resp = await request.get(authorizeURL(baseURL!, challenge), {
      headers: { Accept: "application/json" },
    });
    const body = await resp.json();
    const url = new URL(body.qr_payload);
    const b64 = url.searchParams.get("p")!;
    const payload = JSON.parse(Buffer.from(b64, "base64url").toString("utf-8"));
    expect(payload.origin).toBe("privasys.id");
    expect(payload.rpId).toBe("privasys.id");
    expect(payload.brokerUrl).toBe("wss://relay.privasys.org/relay");
    expect(typeof payload.sessionId).toBe("string");
    expect(payload.sessionId.length).toBeGreaterThan(0);
  });

  test("rejects request without PKCE", async ({ request, baseURL }) => {
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid",
      state: "x",
    });
    const resp = await request.get(`${baseURL}/authorize?${params}`, {
      headers: { Accept: "application/json" },
    });
    expect(resp.status()).toBe(400);
    expect((await resp.json()).error).toBe("invalid_request");
  });

  test("rejects unknown client_id", async ({ request, baseURL }) => {
    const { challenge } = pkce();
    const params = new URLSearchParams({
      client_id: "definitely-not-registered",
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid",
      state: "x",
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const resp = await request.get(`${baseURL}/authorize?${params}`, {
      headers: { Accept: "application/json" },
    });
    expect(resp.status()).toBe(400);
    expect((await resp.json()).error).toBe("invalid_client");
  });

  test("rejects unsupported response_type", async ({ request, baseURL }) => {
    const { challenge } = pkce();
    const params = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: "token",
      scope: "openid",
      state: "x",
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const resp = await request.get(`${baseURL}/authorize?${params}`, {
      headers: { Accept: "application/json" },
    });
    expect(resp.status()).toBe(400);
    expect((await resp.json()).error).toBe("unsupported_response_type");
  });

  test("session is queryable via /session/status", async ({ request, baseURL }) => {
    const { challenge } = pkce();
    const auth = await request
      .get(authorizeURL(baseURL!, challenge), { headers: { Accept: "application/json" } })
      .then((r) => r.json());
    const status = await request
      .get(`${baseURL}/session/status?session_id=${encodeURIComponent(auth.session_id)}`)
      .then((r) => r.json());
    expect(status.authenticated).toBe(false);
  });
});