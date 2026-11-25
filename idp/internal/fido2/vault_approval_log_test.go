// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package fido2

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/tokens"
)

// The log names who asked: the client and session of the bearer and where it
// came from, on one line, with nothing a caller sent able to break the line.
func TestVaultRequester(t *testing.T) {
	iss, err := tokens.NewIssuer(filepath.Join(t.TempDir(), "key.pem"), "https://privasys.id")
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	tok, err := iss.IssueAccessTokenAsserted("user-1", "privasys-platform", "sid-1", nil, nil,
		tokens.Asserted{AuthorizedParty: "privasys-cli"}, time.Minute)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	r := httptest.NewRequest("POST", "/fido2/vault-approval/begin", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7")
	r.Header.Set("User-Agent", "privasys/0.60.2\nforged: line")
	got := vaultRequester(r, iss)
	for _, want := range []string{`client="privasys-cli"`, `sid="sid-1"`, "ip=198.51.100.7", `ua="privasys/0.60.2 forged: line"`} {
		if !strings.Contains(got, want) {
			t.Errorf("requester %q lacks %s", got, want)
		}
	}
	if strings.ContainsAny(got, "\r\n") || strings.Contains(got, tok) {
		t.Fatalf("requester breaks the line or carries the token: %q", got)
	}
	// No bearer worth reading: still a line, with empty names.
	bare := httptest.NewRequest("POST", "/", nil)
	if got := vaultRequester(bare, iss); !strings.Contains(got, `client=""`) || !strings.Contains(got, `sid=""`) {
		t.Fatalf("bare requester = %q", got)
	}
	if got := logField(strings.Repeat("a", 500)); len(got) > 170 {
		t.Fatalf("logField did not clip: %d", len(got))
	}
}
