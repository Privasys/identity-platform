# Auth Broker

A Go WebSocket relay that pairs browser sessions with the Privasys Wallet, with optional OIDC-based app attestation token issuance.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/relay` | WebSocket relay (browser ↔ wallet session pairing) |
| POST | `/notify` | Send push notification to a registered wallet |
| GET | `/healthz` | Health check |
| GET | `/app-challenge` | Get a 32-byte random challenge for app attestation |
| POST | `/app-token` | Exchange App Attest/Play Integrity attestation for an ES256 JWT |
| GET | `/.well-known/openid-configuration` | OIDC discovery document |
| GET | `/jwks` | EC P-256 JSON Web Key Set |

The app-token endpoints are only enabled when a signing key is configured.

## Build

```bash
go build -o auth-broker ./cmd/broker
```

Cross-compile for Linux deployment:

```bash
GOOS=linux GOARCH=amd64 go build -o auth-broker ./cmd/broker
```

## Configuration

All configuration is via environment variables.

| Variable | Required | Description |
|----------|----------|-------------|
| `BROKER_PORT` | No (default: `8090`) | HTTP listen port |
| `SIGNING_KEY_FILE` | For app-token | Path to EC P-256 PEM private key |
| `SIGNING_KEY` | For app-token | EC P-256 PEM private key (inline, alternative to file) |
| `ISSUER_URL` | For app-token | OIDC issuer URL for issued JWTs |
| `AS_AUDIENCE` | For app-token | `aud` claim in issued JWTs |
| `AS_ROLE` | For app-token | Role claim in issued JWTs |
| `APPLE_TEAM_ID` | For app-token | Apple Developer Team ID |
| `APPLE_BUNDLE_ID` | For app-token | iOS app bundle identifier |
| `PRODUCTION` | For app-token | `true` for production, `false` for sandbox App Attest |
| `EXPO_PUSH_URL` | No | Expo push notification endpoint URL |

## App Attestation Token Flow

The broker acts as an OIDC token issuer for app attestation. Mobile apps prove their integrity via iOS App Attest or Android Play Integrity, and receive an ES256 JWT that the attestation server accepts.

```
Wallet                    Broker                    Attestation Server
  │                         │                              │
  │  GET /app-challenge     │                              │
  │────────────────────────>│                              │
  │  { challenge }          │                              │
  │<────────────────────────│                              │
  │                         │                              │
  │  POST /app-token        │                              │
  │  { attestation, ... }   │                              │
  │────────────────────────>│                              │
  │  { token: <ES256 JWT> } │                              │
  │<────────────────────────│                              │
  │                         │                              │
  │  POST / (verify quote)  │                              │
  │  Authorization: Bearer <JWT>                           │
  │───────────────────────────────────────────────────────>│
  │  { success: true }                                     │
  │<───────────────────────────────────────────────────────│
```

### JWT claims

```json
{
  "iss": "https://relay.privasys.org",
  "sub": "wallet",
  "aud": "363481202289541124",
  "platform": "ios",
  "device_id": "...",
  "iat": 1712000000,
  "exp": 1712003600,
  "roles": {
    "attestation-server:client": {}
  }
}
```

### OIDC discovery

The broker exposes standard OIDC endpoints so the attestation server can validate tokens:

- `GET /.well-known/openid-configuration` — returns issuer, jwks_uri, supported algorithms (`ES256`)
- `GET /jwks` — returns the EC P-256 public key in JWK format (`kty: EC`, `crv: P-256`)

## Testing

```bash
go test -v -count=1 ./...
```

The e2e test (`e2e_test.go`) simulates the full mobile app → broker → attestation server flow with 10 subtests covering challenge retrieval, token exchange, OIDC discovery, JWKS validation, JWT signature verification, and error cases.

## Deployment

See [../../.operations/build-and-deploy.md](../../.operations/build-and-deploy.md) for deployment instructions.

## License

[GNU Affero General Public License v3.0](../LICENSE)
