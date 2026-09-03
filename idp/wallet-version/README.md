# Minimum supported wallet version

`version.json` is served at `https://privasys.id/wallet/version.json` and read by
every wallet at launch and on each return to the foreground. A build below a
platform's `minimum` sees the update screen; `level` decides whether that screen
can be dismissed.

It ships with `platforms: {}`, which is no floor at all. That is the correct
resting state: the mechanism is always present, and a floor exists only while
there is a reason for one.

Client: `wallet/src/services/app-version.ts`, tests in
`wallet/src/__tests__/app-version.test.ts`.

## Shape

```json
{
  "schema": 1,
  "issuedAt": "2026-08-29T10:00:00Z",
  "platforms": {
    "ios":     { "minimum": "1.3.92", "level": "required" },
    "android": { "minimum": "1.3.92", "level": "recommended" }
  },
  "notice": {
    "id": "2026-08-29-identity-verification",
    "learnMoreUrl": "https://privasys.org/...",
    "text": {
      "en-GB": {
        "title": "Update to keep verifying your identity",
        "body": "Reading a passport cannot complete on this version.",
        "changes": [
          "Identity verification stops before the document is read.",
          "Nothing else is affected, and no data is at risk."
        ]
      },
      "fr": { "title": "...", "body": "...", "changes": ["..."] }
    }
  }
}
```

`level` is `recommended` (dismissible) or `required` (not). Anything else is
read as `recommended`, so a typo cannot create a wall.

## Rules

**`issuedAt` MUST increase on every edit.** The wallet ignores a manifest older
than the last one it saw, which is what stops a captured copy being replayed to
lower a floor. An edit that forgets to bump it is a no-op on every device that
has already fetched once, and it will look like the deploy worked.

**A floor with no readable `notice.text` is ignored.** The client resolves the
user's language, then the bare language, then `en-GB`, then `en`; if none of
those carries a non-empty title and body, no screen is shown. Nobody is asked to
act without being told why, and that is enforced in the client rather than left
to whoever edits this file.

**Omit a platform to leave it alone.** A fix for one platform is pushed without
touching the other. The Play Integrity fix in 1.3.88 was Android-only; the
device-key change in 1.3.92 mattered on both.

**Give a new message a new `id`.** Dismissals are recorded per id, so reusing
one means users who dismissed the last notice never see this one. Escalating an
existing id from `recommended` to `required` DOES reappear, because a dismissal
is only honoured for a dismissible notice.

**`level: required` is a kill switch for every build below the floor.** Confirm
the replacement is live on both stores before setting it. A user whose device is
too old to install the new build has no way past that screen, and the wallet
holds their identity.

## Trust

`version.json` in this directory is the payload. **What is served is a signed
envelope around it**, built by `sign.cjs` in the deploy:

```json
{ "keyId": "wallet-version-2026-08", "payload": "<base64url of the document>", "sig": "<base64url Ed25519>" }
```

The payload travels encoded so the bytes signed are the bytes verified, with no
canonical-JSON form to agree on. The wallet checks the signature against a key
pinned in its bundle before reading any content.

This matters because `privasys.id` presents an ordinary certificate: the
wallet's RA-TLS client accepts quote-less certs and enforces only when a quote
is present, so there is no attestation to lean on here. Without the pin, a
mis-issued certificate would be enough to publish `required` against an
impossible version and wall the entire installed base. **This is a remote kill
switch, and it should take more than a forged cert to pull it.**

Note what that does NOT protect against: whoever holds the CI secret, and
whoever can merge to `main`. Root on the serving VM is enough to take a floor
DOWN, and not enough to put a false one up, which is the split worth having.

Every failure is read as *no floor*: unsigned, unknown key, bad signature,
malformed payload, unreachable server all land in the same place. That is why
an empty key map is a safe default rather than an open door.

Suppression is the other half, and no signature fixes it: an attacker who drops
the request keeps a wallet on an old build. The client therefore REMEMBERS a
verdict, so going offline does not lift a wall that was already raised.

### Setting up the key, once

```
node idp/wallet-version/gen-key.cjs
```

It prints a public key to pin in
`wallet/src/services/version-signing-keys.ts`, and a private PEM for the
`WALLET_VERSION_SIGNING_KEY` repository secret (with `WALLET_VERSION_KEY_ID`).

**Order matters.** Ship a wallet release carrying the public key and wait for
adoption BEFORE setting the secret. Only builds carrying the key can verify, so
a floor signed by a key nobody has is ignored by every wallet, which looks
exactly like the feature not working.

The pin is a map, so rotation works the same way: add the successor, release,
wait, then switch the secret. Removing the old key strands builds that have not
updated, and a stranded build stops seeing floors entirely.

## Deploying

Edit `version.json`, bump `issuedAt`, push to `main`.
`.github/workflows/deploy-wallet-version.yaml` validates it, signs it, publishes
it, and then re-reads it over real HTTPS: it verifies the signature the way the
wallet will, asserts the payload inside is the document that was committed, and
asserts the cache headers still allow a change to propagate.

The deploy **fails** if the signing secret is absent, rather than publishing
something no wallet would accept.

Check a document without deploying:

```
node idp/wallet-version/validate.cjs idp/wallet-version/version.json
```
