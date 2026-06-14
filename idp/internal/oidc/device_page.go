// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oidc

import (
	_ "embed"
	"net/http"
)

//go:embed device_page.html
var devicePageHTML []byte

// HandleDevicePage serves the device verification page (GET /device). Served
// from the IdP so the whole /device/* namespace (page + lookup/approve/deny)
// has a single owner and needs no reverse-proxy split. The page loads the
// hosted @privasys/auth SDK and talks to the sibling /device/* JSON endpoints.
func HandleDevicePage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(devicePageHTML)
	}
}
