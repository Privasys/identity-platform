// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oidc

import (
	_ "embed"
	"bytes"
	"net/http"
)

//go:embed account_page.html
var accountPageHTML []byte

// HandleAccountPage serves privasys.id/account: the user's platform account
// and billing surface (acting-subject plan v2, part B). Not every user is a
// developer, so this lives beside the identity provider rather than in the
// developer portal: balance, this month's spend by app, the apps allowed to
// spend (with caps and revoke), top-up and membership, recent ledger. The
// page signs the user in with the hosted SDK and calls the management
// service's public account APIs with that bearer; nothing about money enters
// the IdP beyond the spend consents it already keeps.
//
// apiBase is the management-service origin the page calls (the platform's
// public API), substituted into the embedded page once at startup.
func HandleAccountPage(apiBase string) http.HandlerFunc {
	page := bytes.ReplaceAll(accountPageHTML, []byte("__API_BASE__"), []byte(apiBase))
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(page)
	}
}
