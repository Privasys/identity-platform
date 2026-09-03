// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Public keys trusted to sign the minimum-supported-version document.
 *
 * Pinned in the bundle, which is the whole point: the document is served over
 * ordinary TLS from privasys.id, so without a pin the only thing standing
 * between a forged certificate and a walled installed base is the certificate
 * itself. This feature is a remote kill switch; it should take more than a
 * mis-issued cert to pull it.
 *
 * ## An unverifiable document is no document
 *
 * A document that cannot be checked against a key here is IGNORED, exactly as a
 * malformed one is: no floor, and the app carries on. So a wrong or missing key
 * leaves the gate inert rather than leaving it open, which is what makes it safe
 * to ship the pin ahead of the first floor.
 *
 * It also means a typo here is SILENT. Nothing breaks, no wallet complains, and
 * every floor published afterwards is quietly ignored. Two guards exist for
 * that: `__tests__/app-version.test.ts` checks every key here is a real
 * Ed25519 point, and the deploy asserts the public half of the CI signing key
 * is one of these.
 *
 * ## Adding a key
 *
 *   1. `node idp/wallet-version/gen-key.cjs` (prints a keyId, a public key,
 *      and a private PEM; run it somewhere you would be happy running
 *      `ssh-keygen`).
 *   2. Set the PEM as the `WALLET_VERSION_SIGNING_KEY` repository secret, and
 *      the id as `WALLET_VERSION_KEY_ID`. Neither enters this repository.
 *   3. Add the keyId and public key below, and ship a wallet release carrying
 *      them. Only builds containing the key can verify a document signed by it.
 *
 * ## Rotating
 *
 * This is a MAP, not a single key, so a successor ships and reaches the
 * installed base before it is ever used to sign. Rotate by adding the new key,
 * releasing, waiting for adoption, then switching the CI secret. Removing the
 * old key strands every build that has not updated: those wallets stop
 * verifying, which means they stop seeing floors, which is the failure this
 * feature exists to avoid.
 */

/** keyId -> base64url Ed25519 public key (32 bytes). */
export const VERSION_SIGNING_KEYS: Readonly<Record<string, string>> = {
    'wallet-version-2026-09': '6o24GOySbNHTOizld4AbIWTjtzMuLBRUu1tfhnZ7phE',
};
