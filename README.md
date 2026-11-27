# Privasys Identity Platform

A monorepo for Privasys authentication: the **Privasys Wallet** mobile app, the `@privasys/auth` browser SDK, the authentication broker, and the **Privasys ID** OIDC identity provider. Authenticate to web applications using hardware-attested enclaves, FIDO2-grade cryptography, and on-device biometrics. No passwords.No trust assumptions.

## Repository Structure

| Directory | Description |
|-----------|-------------|
| `wallet/` | Expo / React Native mobile app (iOS & Android) |
| `sdk/` | `@privasys/auth` — TypeScript browser SDK for relying parties |
| `broker/` | Go WebSocket relay that pairs browser sessions with the wallet |
| `chip-placement/` | Where the NFC chip is in each country's passport, with a source for every entry. [Contributions welcome](chip-placement/README.md) |

### SDK Features

- **`AuthFrame`**: one per page. `connect()` restores the person's session or runs the sign-in gate (the Privasys ID wallet by QR code or notification, passkeys, external identity providers), presented as a page, a modal, inline or headless, with the site's theme. `app(host)` opens the channel to an enclave app: sealed for a wallet session, direct with an audience token otherwise. `token()`, `renew()`, `signOut()` and `onSessionChange()` keep every tab of the site in step.
- **`IdpGate`** (`@privasys/auth/idp`): the gate of the identity provider's own pages, which approve a device's sign-in or an operation.
- **Hosted bundle**: `https://privasys.id/auth/privasys-auth-client.iife.js` gives `window.Privasys.AuthFrame` and `Privasys.IdpGate` without a build step.

### Wallet Features

- **RA-TLS attestation** — Native Rust module verifies SGX/TDX enclave certificates on-device
- **Hardware-bound FIDO2** — P-256 keys in Secure Enclave (iOS) / StrongBox (Android)
- **App attestation** — iOS App Attest / Android Play Integrity proves app integrity to the attestation server
- **Trusted apps** — Trust-on-first-use with change detection (like SSH `known_hosts`)
- **Biometric grace period** — Skip re-prompt for trusted apps within configurable window
- **Batch auth** — Verify and sign in to multiple enclaves with a single biometric prompt
- **Custom splash animation** — Diagonal shapes slide apart to reveal the app
- **iOS Credential Provider** — AutoFill passkey extension for third-party WebAuthn flows

## Quick Start

### Wallet (mobile app)

```bash
cd wallet
bun install
bun start          # Expo dev server
```

### SDK

```bash
cd sdk
bun install
bun run build      # Compiles to dist/
```

### Broker

```bash
cd broker
go build -o auth-broker ./cmd/broker
./auth-broker      # Listens on :8090
```

See [broker/README.md](broker/README.md) for configuration, app-token endpoints, and deployment.

## How It Works

1. A relying party embeds the `@privasys/auth` SDK.
2. The SDK generates a session and displays a QR code.
3. The user scans the QR with Privasys Wallet.
4. The wallet performs RA-TLS attestation against the platform's enclaves.
5. On success, the wallet signs a FIDO2 assertion using on-device biometrics.
6. The signed result is relayed back to the SDK through the broker.

All private keys stay on-device. The broker only relays opaque messages, it never sees credentials.

## Building

The wallet includes native Rust modules for RA-TLS verification. See [`.github/workflows/build-wallet.yaml`](.github/workflows/build-wallet.yaml) for the full CI/CD pipeline, including cross-compilation for iOS and Android.

## Testing

```bash
cd wallet
npx jest               # Run all tests
npx jest --verbose     # With detailed output
```

The test suite covers the FIDO2 registration and authentication ceremonies, including wire format validation, WebAuthn compliance, and CBOR structure checks.

## License

[GNU Affero General Public License v3.0](LICENSE)
