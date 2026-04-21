// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Recovery happy-path spec.
 *
 * Flow:
 *   1. Software wallet registers a new FIDO2 credential at the IdP
 *      → server returns a sessionToken + auto-generated 24-word phrase.
 *   2. Use sessionToken to call /recovery/phrase/regenerate → new phrase.
 *   3. Verify /recovery/phrase/status reports `has_phrase: true`.
 *   4. Simulate device loss: discard local credentialId, call
 *      /recovery/begin with the phrase → recovery_request approved
 *      (no guardians configured for fresh test user).
 *   5. /recovery/complete → revokes old credentials.
 *   6. Re-register a FIDO2 credential under the same userHandle.
 */
import { test, expect } from "@playwright/test";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

import {
  fido2Register,
  fido2Authenticate,
  loadOrCreateIdentity,
} from "./lib/fido2-client";

const ISSUER = process.env.IDP_BASE_URL ?? "https://privasys.id";
const RP_ID = new URL(ISSUER).hostname;

function freshIdentity() {
  const dir = mkdtempSync(join(tmpdir(), "idp-e2e-recovery-"));
  const file = join(dir, "id.json");
  return { id: loadOrCreateIdentity(file), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test.describe("recovery happy path", () => {
  test("register → regenerate phrase → recover → re-register", async () => {
    const { id, cleanup } = freshIdentity();
    try {
      // 1. Register fresh identity (no session_id — standalone, no OIDC).
      const reg = await fido2Register(ISSUER, RP_ID, id, "", "Recovery Test User");
      expect(reg.sessionToken).toBeTruthy();
      expect(reg.userId).toBeTruthy();
      // First-registration recovery phrase MAY be present (server generates
      // one automatically) but we'll regenerate it explicitly anyway.

      // 2. Regenerate phrase via wallet sessionToken.
      const regen = await fetch(`${ISSUER}/recovery/phrase/regenerate`, {
        method: "POST",
        headers: { Authorization: `Bearer wallet:${reg.sessionToken}` },
      });
      expect(regen.status).toBe(200);
      const regenBody = (await regen.json()) as { phrase: string };
      const phrase = regenBody.phrase;
      expect(typeof phrase).toBe("string");
      expect(phrase.split(/\s+/)).toHaveLength(24);

      // 3. Status check — phrase must be present.
      const status = await fetch(
        `${ISSUER}/recovery/phrase/status?user_id=${encodeURIComponent(reg.userId)}`,
      );
      expect(status.status).toBe(200);
      const statusBody = (await status.json()) as { has_phrase: boolean };
      expect(statusBody.has_phrase).toBe(true);

      // 4. Recovery begin.
      const begin = await fetch(`${ISSUER}/recovery/begin`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ recovery_phrase: phrase }),
      });
      expect(begin.status).toBe(200);
      const beginBody = (await begin.json()) as {
        request_id: string;
        user_id: string;
        status: string;
      };
      expect(beginBody.user_id).toBe(reg.userId);
      expect(beginBody.status).toBe("approved");

      // 5. Recovery complete.
      const complete = await fetch(`${ISSUER}/recovery/complete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: beginBody.request_id }),
      });
      expect(complete.status).toBe(200);
      const completeBody = (await complete.json()) as { status: string; user_id: string };
      expect(completeBody.status).toBe("completed");
      expect(completeBody.user_id).toBe(reg.userId);

      // 6. After recovery, the OLD credentialId is revoked. Authentication
      //    with it must fail.
      try {
        await fido2Authenticate(ISSUER, RP_ID, id, "");
        throw new Error("expected authentication to fail after recovery");
      } catch (e) {
        const status = (e as Error & { status?: number }).status;
        expect(status).toBeGreaterThanOrEqual(400);
      }

      // 7. Re-register a new credential under the SAME userHandle.
      id.credentialId = undefined;
      id.persisted.credentialId = undefined;
      const re = await fido2Register(ISSUER, RP_ID, id, "", "Recovery Test User");
      expect(re.sessionToken).toBeTruthy();
      expect(re.userId).toBe(reg.userId);

      // 8. New credential authenticates.
      const auth = await fido2Authenticate(ISSUER, RP_ID, id, "");
      expect(auth.sessionToken).toBeTruthy();
      expect(auth.userId).toBe(reg.userId);
    } finally {
      cleanup();
    }
  });

  test("invalid recovery phrase is rejected", async () => {
    const fake =
      "abandon ability able about above absent absorb abstract absurd " +
      "abuse access accident account accuse achieve acid acoustic acquire " +
      "across act action actor actress";
    const begin = await fetch(`${ISSUER}/recovery/begin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ recovery_phrase: fake }),
    });
    expect(begin.status).toBe(400);
  });
});
