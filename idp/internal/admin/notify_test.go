package admin

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// TestSealToWallet_RoundTrip locks the envelope format the wallet
// mirrors: base64url( eph_pub(32) || nonce(24) || ct ), key =
// HKDF-SHA256(X25519(eph, wallet), info="privasys-notify-v1"),
// AAD = notification type.
func TestSealToWallet_RoundTrip(t *testing.T) {
	curve := ecdh.X25519()
	walletPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	walletPubB64 := base64.RawURLEncoding.EncodeToString(walletPriv.PublicKey().Bytes())

	payload := []byte(`{"attributes":{"name":"Alice Example"},"node_name":"report.pdf"}`)
	sealed, err := sealToWallet(walletPubB64, "share-request", payload)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 32+chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		t.Fatalf("envelope too short: %d", len(raw))
	}
	ephPub, err := curve.NewPublicKey(raw[:32])
	if err != nil {
		t.Fatal(err)
	}
	shared, err := walletPriv.ECDH(ephPub)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, []byte(notifySealInfo)), key); err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := raw[32 : 32+chacha20poly1305.NonceSizeX]
	ct := raw[32+chacha20poly1305.NonceSizeX:]
	got, err := aead.Open(nil, nonce, ct, []byte("share-request"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("round trip = %q", got)
	}
	// Wrong AAD (type) must fail: the type is authenticated.
	if _, err := aead.Open(nil, nonce, ct, []byte("share-decision")); err == nil {
		t.Fatal("wrong type must not decrypt")
	}
}

// TestSealToWallet_BadKey rejects malformed keys.
func TestSealToWallet_BadKey(t *testing.T) {
	for _, k := range []string{"", "short", base64.RawURLEncoding.EncodeToString(make([]byte, 16))} {
		if _, err := sealToWallet(k, "t", []byte("x")); err == nil {
			t.Fatalf("key %q should fail", k)
		}
	}
}
