#!/usr/bin/env bash
# Copyright (c) Privasys. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Install wallet locale packs and their Caddy route on idp-fr-par-1.
#
# Run ON THE VM by .github/workflows/deploy-i18n-packs.yaml, which uploads
# this script alongside /tmp/i18n-packs.tar.gz and /tmp/i18n.caddy.
#
# Two invariants this script exists to protect:
#
#   1. Deploys are ADDITIVE. Pack URLs are content-addressed by manifest
#      version, and an app build in the wild only ever requests the version
#      it was compiled against. Removing an old version directory strands
#      those users on English for any language they have not cached. So we
#      unpack alongside, never `rsync --delete`.
#
#   2. The Caddyfile is never left broken. privasys.id is the IdP for the
#      whole fleet; a bad reload takes down sign-in everywhere. Every edit
#      is backed up, validated, and rolled back on failure before reload.

set -euo pipefail

TARBALL=/tmp/i18n-packs.tar.gz
SNIPPET_SRC=/tmp/i18n.caddy
WEBROOT=/var/www/i18n
CADDYFILE=/etc/caddy/Caddyfile
CONFD=/etc/caddy/conf.d
SNIPPET_DST="${CONFD}/i18n.caddy"

# ~1.1 MB per version, so retention is cheap. Keeping 20 means an app build
# has to be ~20 catalogue revisions stale before its packs disappear, and it
# still degrades to English rather than breaking.
KEEP_VERSIONS=20

log() { printf '==> %s\n' "$*"; }

[ -f "$TARBALL" ] || { echo "missing $TARBALL" >&2; exit 1; }
[ -f "$SNIPPET_SRC" ] || { echo "missing $SNIPPET_SRC" >&2; exit 1; }

# ---------------------------------------------------------------- packs ---

log "Unpacking locale packs into ${WEBROOT}"
sudo mkdir -p "$WEBROOT"
# Additive by construction: tar writes <version>/<tag>.json and leaves every
# other version directory untouched.
sudo tar -xzf "$TARBALL" -C "$WEBROOT"
sudo chown -R root:root "$WEBROOT"
sudo find "$WEBROOT" -type d -exec chmod 755 {} +
sudo find "$WEBROOT" -type f -exec chmod 644 {} +

log "Versions now present:"
sudo ls -1t "$WEBROOT"

# ---------------------------------------------------------------- caddy ---

log "Installing ${SNIPPET_DST}"
sudo mkdir -p "$CONFD"
# Write the snippet BEFORE adding the import, so the glob never resolves to
# an empty set during validation.
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
    # Insert immediately after the `privasys.id {` opening line. Two reasons
    # for that exact position:
    #
    #   * Anchored to the start of the line, so `dev.privasys.id {` and any
    #     hostname mentioned inside another block cannot match.
    #   * FIRST inside the block, so the i18n route is evaluated before the
    #     site's `@withExt path_regexp \.[A-Za-z0-9]+$` catch-all, which
    #     would otherwise serve the packs without cache or CORS headers and
    #     look like it had worked. See idp/caddy/i18n.caddy.
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
# `caddy reload` drives the admin API of the running process; fall back to
# systemd if the admin endpoint is not reachable, matching how the rest of
# this host is operated.
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

log "Pruning old pack versions (keep ${KEEP_VERSIONS})"
sudo bash -c "cd '${WEBROOT}' && ls -1t | tail -n +$((KEEP_VERSIONS + 1)) | xargs -r rm -rf"

rm -f "$TARBALL" "$SNIPPET_SRC"
log "Done"
