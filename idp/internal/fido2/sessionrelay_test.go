// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package fido2

import (
	"encoding/base64"
	"encoding/hex"
	"net/http/httptest"
	"testing"
)

// TestSessionRelayBinding_KAT locks the wire contract for the WebAuthn
// binding challenge used in the session-relay flow. Any change to the
// digest layout MUST also be mirrored in:
//
//   - auth/wallet/src/services/fido2.ts ::computeSessionRelayBinding
//   - any future relying-party verifier
//
// The vectors below are deterministic — re-running the test on any
// platform must produce the same output.
func TestSessionRelayBinding_KAT(t *testing.T) {
	zero := func(n int) []byte { return make([]byte, n) }
	cases := []struct {
		name        string
		nonceB64    string // base64url, no padding
		sdkPubB64   string
		quoteHex    string // hex
		encPubB64   string
		sessB64     string // base64url, no padding (matches enclave manager wire format)
		wantBindB64 string // base64url, no padding (what the wallet would set as challenge)
	}{
		{
			// All-zero inputs of canonical sizes (32B nonce, 65B SEC1 pubkeys,
			// 32B quote hash, 16B session id). This vector exists so any
			// implementation can validate its byte layout / domain separator
			// without needing a working ECDH stack.
			name:        "all-zero",
			nonceB64:    base64.RawURLEncoding.EncodeToString(zero(32)),
			sdkPubB64:   base64.RawURLEncoding.EncodeToString(append([]byte{0x04}, zero(64)...)),
			quoteHex:    hex.EncodeToString(zero(32)),
			encPubB64:   base64.RawURLEncoding.EncodeToString(append([]byte{0x04}, zero(64)...)),
			sessB64:     base64.RawURLEncoding.EncodeToString(zero(16)),
			wantBindB64: "OziFEdCpT4RDFtjziC_vA4r1wvdNQ-DGQ8U7xL8vbic",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := computeSessionRelayBinding(tc.nonceB64, tc.sdkPubB64, tc.quoteHex, tc.encPubB64, tc.sessB64)
			if err != nil {
				t.Fatalf("computeSessionRelayBinding: %v", err)
			}
			gotB64 := base64.RawURLEncoding.EncodeToString(got)
			if gotB64 != tc.wantBindB64 {
				t.Fatalf("binding mismatch\n  got  %s\n  want %s", gotB64, tc.wantBindB64)
			}
		})
	}
}

func TestSessionRelayBinding_RejectsBadInputs(t *testing.T) {
	if _, err := computeSessionRelayBinding("!!!", "", "", "", ""); err == nil {
		t.Fatal("expected error on invalid base64url")
	}
}

func TestEnforceSessionRelayBinding_NoSessionID(t *testing.T) {
	r := httptest.NewRequest("GET", "/?challenge=foo", nil)
	if err := enforceSessionRelayBinding(r, "foo"); err != nil {
		t.Fatalf("non-relay flow must be a no-op, got %v", err)
	}
}

func TestEnforceSessionRelayBinding_MissingInputs(t *testing.T) {
	r := httptest.NewRequest("GET", "/?session_id=00", nil)
	if err := enforceSessionRelayBinding(r, "ignored"); err == nil {
		t.Fatal("expected error when binding inputs are missing")
	}
}

func TestEnforceSessionRelayBinding_Mismatch(t *testing.T) {
	zero := func(n int) []byte { return make([]byte, n) }
	q := "session_id=" + hex.EncodeToString(zero(16)) +
		"&nonce=" + base64.RawURLEncoding.EncodeToString(zero(32)) +
		"&sdk_pub=" + base64.RawURLEncoding.EncodeToString(append([]byte{0x04}, zero(64)...)) +
		"&enc_pub=" + base64.RawURLEncoding.EncodeToString(append([]byte{0x04}, zero(64)...)) +
		"&quote_hash=" + hex.EncodeToString(zero(32))
	r := httptest.NewRequest("GET", "/?"+q, nil)
	wrong := base64.RawURLEncoding.EncodeToString(zero(32))
	if err := enforceSessionRelayBinding(r, wrong); err == nil {
		t.Fatal("expected mismatch to be rejected")
	}
}

func TestEnforceSessionRelayBinding_Match(t *testing.T) {
	zero := func(n int) []byte { return make([]byte, n) }
	q := "session_id=" + hex.EncodeToString(zero(16)) +
		"&nonce=" + base64.RawURLEncoding.EncodeToString(zero(32)) +
		"&sdk_pub=" + base64.RawURLEncoding.EncodeToString(append([]byte{0x04}, zero(64)...)) +
		"&enc_pub=" + base64.RawURLEncoding.EncodeToString(append([]byte{0x04}, zero(64)...)) +
		"&quote_hash=" + hex.EncodeToString(zero(32))
	r := httptest.NewRequest("GET", "/?"+q, nil)
	binding, err := computeSessionRelayBinding(
		base64.RawURLEncoding.EncodeToString(zero(32)),
		base64.RawURLEncoding.EncodeToString(append([]byte{0x04}, zero(64)...)),
		hex.EncodeToString(zero(32)),
		base64.RawURLEncoding.EncodeToString(append([]byte{0x04}, zero(64)...)),
		hex.EncodeToString(zero(16)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := enforceSessionRelayBinding(r, base64.RawURLEncoding.EncodeToString(binding)); err != nil {
		t.Fatalf("expected match, got %v", err)
	}
}
