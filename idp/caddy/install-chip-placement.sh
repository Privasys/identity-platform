#!/usr/bin/env bash
# Copyright (c) Privasys. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Install the chip-placement list and its Caddy route on idp-fr-par-1.
#
# Run ON THE VM by .github/workflows/deploy-chip-placement.yaml, which uploads
# this script alongside /tmp/chip-placement.json and /tmp/chip-placement.caddy.
#
# /tmp/chip-placement.json is a SIGNED ENVELOPE, wrapped by the workflow before
# upload. Nothing on this host holds the signing key, so nothing here can
# produce a list a wallet would accept.
#
# The same two invariants as install-wallet-version.sh:
#
#   1. The document is REPLACED atomically, so a fetch mid-deploy gets the old
#      list or the new one, never a truncated file.
#
#   2. The Caddyfile is never left broken. privasys.id is the IdP for the whole
#      fleet; a bad reload takes down sign-in everywhere. Every edit is backed
#      up, validated, and rolled back on failure before reload.

set -euo pipefail

DOC_SRC=/tmp/chip-placement.json
SNIPPET_SRC=/tmp/chip-placement.caddy
WEBROOT=/var/www/chip-placement
CADDYFILE=/etc/caddy/Caddyfile
CONFD=/etc/caddy/conf.d
SNIPPET_DST="${CONFD}/chip-placement.caddy"

log() { printf '==> %s\n' "$*"; }

[ -f "$DOC_SRC" ] || { echo "missing $DOC_SRC" >&2; exit 1; }
[ -f "$SNIPPET_SRC" ] || { echo "missing $SNIPPET_SRC" >&2; exit 1; }

# Refuse to publish something the wallet cannot read: it would ignore it and
# keep the list it has, and the deploy would look as if it had worked.
if command -v python3 >/dev/null 2>&1; then
    log "Validating the envelope"
    python3 - "$DOC_SRC" <<'PY'
import json, sys
env = json.load(open(sys.argv[1]))
missing = [k for k in ("keyId", "payload", "sig") if not isinstance(env.get(k), str) or not env[k]]
if missing:
    sys.exit("envelope is missing: " + ", ".join(missing))
print("envelope ok, signed by", env["keyId"])
PY
fi

# ------------------------------------------------------------- document ---

log "Publishing ${WEBROOT}/chip-placement.json"
sudo mkdir -p "$WEBROOT"
# Same filesystem, so the rename is atomic: readers see one document or the
# other, never a partial write.
sudo cp "$DOC_SRC" "${WEBROOT}/.chip-placement.json.new"
sudo chown root:root "${WEBROOT}/.chip-placement.json.new"
sudo chmod 644 "${WEBROOT}/.chip-placement.json.new"
sudo mv -f "${WEBROOT}/.chip-placement.json.new" "${WEBROOT}/chip-placement.json"
sudo chmod 755 "$WEBROOT"

log "Now serving (envelope; the payload is base64url and is not meant to be read here):"
sudo cat "${WEBROOT}/chip-placement.json"

# ---------------------------------------------------------------- caddy ---

log "Installing ${SNIPPET_DST}"
sudo mkdir -p "$CONFD"
# Write the snippet BEFORE adding the import, so the glob never resolves to an
# empty set during validation.
sudo cp "$SNIPPET_SRC" "$SNIPPET_DST"
sudo chown root:root "$SNIPPET_DST"
sudo chmod 644 "$SNIPPET_DST"

BACKUP="${CADDYFILE}.bak.$(date +%s)"
sudo cp "$CADDYFILE" "$BACKUP"
log "Backed up Caddyfile to ${BACKUP}"

if sudo grep -qF 'import conf.d/*.caddy' "$CADDYFILE"; then
    log "import line already present, leaving Caddyfile untouched"
else
    log "Adding import to the privasys.id site block"
    # Anchored to the start of the line so `dev.privasys.id {` cannot match, and
    # inserted FIRST inside the block so this route is evaluated before the
    # site's `@withExt` catch-all. See idp/caddy/chip-placement.caddy.
    sudo awk '
        !done && /^[[:space:]]*privasys\.id[[:space:]]*\{/ {
            print
            print "    import conf.d/*.caddy"
            done = 1
            next
        }
        { print }
        END { if (!done) exit 3 }
    ' "$CADDYFILE" | sudo tee "${CADDYFILE}.new" >/dev/null || {
        echo "could not find a 'privasys.id {' site block in ${CADDYFILE}" >&2
        sudo rm -f "${CADDYFILE}.new"
        exit 1
    }
    sudo mv "${CADDYFILE}.new" "$CADDYFILE"
fi

log "Validating Caddy config"
if ! sudo caddy validate --config "$CADDYFILE" --adapter caddyfile; then
    echo "caddy validate FAILED, restoring ${BACKUP}" >&2
    sudo cp "$BACKUP" "$CADDYFILE"
    sudo rm -f "$SNIPPET_DST"
    exit 1
fi

log "Reloading Caddy"
if ! { sudo caddy reload --config "$CADDYFILE" --adapter caddyfile || sudo systemctl reload caddy; }; then
    echo "caddy reload FAILED, restoring ${BACKUP} and reloading" >&2
    sudo cp "$BACKUP" "$CADDYFILE"
    sudo rm -f "$SNIPPET_DST"
    sudo caddy reload --config "$CADDYFILE" --adapter caddyfile || \
        sudo systemctl reload caddy || true
    exit 1
fi

# --------------------------------------------------------------- tidy up ---

log "Pruning Caddyfile backups (keep 5)"
sudo bash -c "ls -1t ${CADDYFILE}.bak.* 2>/dev/null | tail -n +6 | xargs -r rm -f"

rm -f "$DOC_SRC" "$SNIPPET_SRC"
log "Done"
