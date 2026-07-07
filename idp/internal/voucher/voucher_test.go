// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package voucher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/tokens"
)

func testIssuer(t *testing.T) *tokens.Issuer {
	t.Helper()
	iss, err := tokens.NewIssuer(filepath.Join(t.TempDir(), "key.pem"), "https://privasys.id")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss
}

// TestMint reserves via a fake mgmt reserve endpoint and signs one voucher per
// per-provider grant, each verifiable against the issuer and carrying the RP +
// provider + claims (and no user identity).
func TestMint(t *testing.T) {
	const token = "s3cret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body struct {
			RPAccountID string   `json:"rp_account_id"`
			Attributes  []string `json:"attributes"`
			TTLSeconds  int64    `json:"ttl_seconds"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if len(body.Attributes) != 3 || body.TTLSeconds != 1800 {
			t.Errorf("unexpected reserve body: %+v", body)
		}
		// Two providers → two grants.
		json.NewEncoder(w).Encode(map[string]any{"grants": []Grant{
			{VoucherJTI: "j1", ProviderNamespace: "privasys", IssuerURL: "https://privasys.id",
				Claims: []string{"privasys:age_over", "privasys:document_valid"}, PriceCredits: 20000},
			{VoucherJTI: "j2", ProviderNamespace: "acme-dna", IssuerURL: "https://acme.example",
				Claims: []string{"acme-dna:brca1_status"}, PriceCredits: 50000},
		}})
	}))
	defer srv.Close()

	m := NewMinter(testIssuer(t), srv.URL, token)
	if !m.Enabled() {
		t.Fatal("minter should be enabled")
	}
	vs, err := m.Mint(context.Background(), "11111111-1111-1111-1111-111111111111", "acme.example",
		[]string{"privasys:age_over", "privasys:document_valid", "acme-dna:brca1_status"}, 30*time.Minute)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(vs) != 2 {
		t.Fatalf("expected 2 vouchers (one per provider), got %d", len(vs))
	}
	// The first voucher verifies and binds RP + provider, no user identity.
	claims, err := m.issuer.VerifyAccessToken(vs[0].Token)
	if err != nil {
		t.Fatalf("verify voucher: %v", err)
	}
	if claims["rp_id"] != "acme.example" || claims["provider"] != "privasys" || claims["jti"] != "j1" {
		t.Fatalf("voucher claims wrong: %+v", claims)
	}
	if _, has := claims["sub"]; has {
		t.Fatal("voucher must carry no user identity")
	}
}

// TestMintInsufficient surfaces the ledger's 402 as ErrInsufficient.
func TestMintInsufficient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()
	m := NewMinter(testIssuer(t), srv.URL, "t")
	_, err := m.Mint(context.Background(), "11111111-1111-1111-1111-111111111111", "rp", []string{"privasys:age_over"}, time.Minute)
	if err != ErrInsufficient {
		t.Fatalf("expected ErrInsufficient, got %v", err)
	}
}

// TestMintDisabled: with no mgmt endpoint the minter is a no-op (the IdP runs
// without the marketplace configured).
func TestMintDisabled(t *testing.T) {
	m := NewMinter(testIssuer(t), "", "")
	vs, err := m.Mint(context.Background(), "acc", "rp", []string{"privasys:age_over"}, time.Minute)
	if err != nil || vs != nil {
		t.Fatalf("disabled minter should no-op, got (%v, %v)", vs, err)
	}
}
