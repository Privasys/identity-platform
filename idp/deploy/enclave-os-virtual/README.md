# Deploying the IdP on Enclave OS Virtual (TDX)

## Overview

The Privasys IdP runs as a container inside an enclave-os-virtual TDX
confidential VM. The signing key and SQLite database are stored on a
per-container LUKS2+AEAD encrypted volume with a BYOK passphrase that
you generate and keep safe.

**What this gives you:**
- The IdP binary is attestable — RA-TLS certificates prove it's running
  exactly the published image, inside a hardware TEE.
- The signing key and database are encrypted at rest with a key you control.
- If the VM dies, you can mount the LUKS partition on another machine using
  your passphrase and recover all data.

## Prerequisites

- An enclave-os-virtual image (v0.12+) deployed to a TDX-capable host
- Docker and `docker buildx` (for multi-arch builds)
- A GHCR token with `write:packages` permission

## Step 1 — Build and push the container image

```bash
cd auth/idp

# Build for linux/amd64 (TDX hosts are x86_64)
docker buildx build --platform linux/amd64 \
  -t ghcr.io/privasys/idp:latest \
  --push .

# Note the digest from the push output, e.g.:
#   ghcr.io/privasys/idp@sha256:abc123...
```

Pin the digest in `manifest.yaml` — enclave-os-virtual requires
digest-pinned images (no mutable tags).

## Step 2 — Generate the BYOK passphrase

```bash
# Generate a 256-bit passphrase
openssl rand -base64 32
# Example: aBc1DeF2gHiJ3kLm4nOpQrSt5uVwXyZ6/AbCdE==
```

**Store this passphrase in your password manager.** If you lose it, the
encrypted volume is unrecoverable.

## Step 3 — Generate the admin token

```bash
openssl rand -hex 32
# Example: 02da67bae333e213261a19847da1c17eebaf08c4ade96fdf389b23c63d4b3a63
```

This token is passed as `vault_token` at container load time. It is NOT
measured into attestation — you can rotate it without changing the
attested configuration.

## Step 4 — Deploy to enclave-os-virtual

### Option A: Static manifest (recommended for the IdP)

Copy `manifest.yaml` to `/data/manifest.yaml` on the enclave-os-virtual
instance. The manager loads it at boot before the API is available —
no authentication needed. The BYOK storage key is passed via instance
metadata (GCP) or the manager API on first boot.

### Option B: API-based deployment

```bash
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  -X POST https://manager.privasys.id/api/v1/containers \
  -d '{
    "name": "idp",
    "image": "ghcr.io/privasys/idp@sha256:DIGEST",
    "hostname": "privasys.id",
    "port": 8091,
    "storage": "1G",
    "storage_key": "YOUR_BYOK_PASSPHRASE",
    "vault_token": "YOUR_ADMIN_TOKEN",
    "env": {
      "IDP_PORT": "8091",
      "IDP_ISSUER_URL": "https://privasys.id",
      "IDP_RP_ID": "privasys.id",
      "IDP_RP_ORIGINS": "https://privasys.id",
      "IDP_BROKER_URL": "https://relay.privasys.org"
    },
    "health_check": {
      "http": "http://127.0.0.1:8091/healthz",
      "interval_seconds": 10,
      "timeout_seconds": 3,
      "retries": 3
    }
  }'
```

## Step 5 — Migrate existing data

If you have an existing IdP running on a plain VM, copy the signing key
and database into the container volume:

```bash
# On the old host
scp /var/lib/privasys/idp.db new-host:/tmp/
scp /etc/privasys/idp-signing-key.pem new-host:/tmp/

# On the enclave-os-virtual host (after LUKS volume is mounted)
cp /tmp/idp.db /run/containers/idp/idp.db
cp /tmp/idp-signing-key.pem /run/containers/idp/signing-key.pem
```

The IdP will pick up the existing data and signing key on next start.
All existing tokens, credentials, and clients remain valid.

## Step 6 — Verify attestation

From any machine with the RA-TLS client:

```bash
ra-tls-verify privasys.id:443 \
  --expected-image-digest sha256:DIGEST \
  --expected-dek-origin byok:FINGERPRINT
```

The certificate will contain:
- **OID 3.2** — Container image digest (must match your published image)
- **OID 3.4** — Volume encryption origin (`byok:<sha256 of passphrase>`)
- **OID 1.1** — Platform config Merkle root (includes the IdP config)

## Data Recovery

If the VM is lost, create a new instance and attach the old disk:

```bash
# Attach the disk, then open the LUKS partition
printf '%s' 'YOUR_BYOK_PASSPHRASE' | \
  cryptsetup luksOpen /dev/sdb_container_vol data-recovery --key-file=-
mount /dev/mapper/data-recovery /mnt/recovery

# Copy idp.db and signing-key.pem to the new instance
ls /mnt/recovery/
# idp.db  signing-key.pem
```

## Parallel Run Strategy

For zero-downtime migration:

1. Deploy the containerized IdP alongside the existing bare-metal one
2. Both share the same signing key (same JWTs are valid from either)
3. Point `privasys.id` DNS to the containerized instance
4. Monitor for 24h, verify wallet login + portal auth + management service
5. Decommission the bare-metal IdP
