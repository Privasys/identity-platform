#!/usr/bin/env bash
# Copyright (c) Privasys. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Install the minimum-supported-version document and its Caddy route on
# idp-fr-par-1.
#
# Run ON THE VM by .github/workflows/deploy-wallet-version.yaml, which uploads
# this script alongside /tmp/version.json and /tmp/wallet-version.caddy.
#
# /tmp/version.json is a SIGNED ENVELOPE, not the bare document: the workflow
# wraps it before upload. Nothing on this host holds the signing key, and
# nothing here can produce a document a wallet would accept. That is the point:
# root on this VM is enough to take the floor DOWN, and not enough to put a
# false one up.
#
# Two invariants, the same two install-i18n.sh protects, for different reasons:
#
#   1. The document is REPLACED, not accumulated. Unlike the locale packs it is
#      mutable and singular, and the whole point is that every wallet sees the
#      current one. It is written atomically so a fetch mid-deploy gets either
#      the old document or the new one, never a truncated file: a half-written
#      document parses as garbage, and garbage means "no floor", which would
#      silently drop a wall that was meant to be up.
#
#   2. The Caddyfile is never left broken. privasys.id is the IdP for the whole
#      fleet; a bad reload takes down sign-in everywhere. Every edit is backed
#      up, validated, and rolled back on failure before reload.

set -euo pipefail

DOC_SRC=/tmp/version.json
SNIPPET_SRC=/tmp/wallet-version.caddy
WEBROOT=/var/www/wallet-version
CADDYFILE=/etc/caddy/Caddyfile
CONFD=/etc/caddy/conf.d
SNIPPET_DST="${CONFD}/wallet-version.caddy"

log() { printf '==> %s\n' "$*"; }

[ -f "$DOC_SRC" ] || { echo "missing $DOC_SRC" >&2; exit 1; }
[ -f "$SNIPPET_SRC" ] || { echo "missing $SNIPPET_SRC" >&2; exit 1; }

# Refuse to publish something the wallet cannot read. Anything unparseable, or
# any envelope missing a field, means "no floor" on every device, so a mangled
# upload would quietly disarm the gate rather than break loudly.
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

log "Publishing ${WEBROOT}/version.json"
sudo mkdir -p "$WEBROOT"
# Same filesystem, so the rename is atomic: readers see one document or the
# other, never a partial write.
sudo cp "$DOC_SRC" "${WEBROOT}/.version.json.new"
sudo chown root:root "${WEBROOT}/.version.json.new"
sudo chmod 644 "${WEBROOT}/.version.json.new"
sudo mv -f "${WEBROOT}/.version.json.new" "${WEBROOT}/version.json"
sudo chmod 755 "$WEBROOT"

log "Now serving (envelope; the payload is base64url and is not meant to be read here):"
sudo cat "${WEBROOT}/version.json"

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
    # site's `@withExt` catch-all. See idp/caddy/wallet-version.caddy.
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
