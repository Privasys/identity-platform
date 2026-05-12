// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessions

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// TestEncAuthRoundTrip exercises EncAuthCanonicalCBOR + VerifyES256Raw
// end-to-end without needing the SQLite store, so it runs under
// CGO_ENABLED=0 (no //go:build cgo guard).
func TestEncAuthRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hwPub := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	if len(hwPub) == 33 { // we want uncompressed; switch encoding
		hwPub = elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	}
	if len(hwPub) != 65 || hwPub[0] != 0x04 {
		t.Fatalf("expected SEC1 uncompressed, got %d bytes prefix=%x", len(hwPub), hwPub[0])
	}

	p := &EncAuth{
		V:         1,
		Sub:       "user-1",
		SID:       "sid-abc",
		AppID:     bytes32(0xa1),
		EncMeas:   bytes32(0xe1),
		EncPub:    sec1Pub(),
		QuoteHash: bytes32(0xb2),
		NotBefore: 1_000,
		NotAfter:  2_000,
		HwPub:     hwPub,
	}
	enc, err := EncAuthCanonicalCBOR(p)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(enc)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):], sb)

	if err := VerifyES256Raw(hwPub, sig, enc); err != nil {
		t.Fatalf("verify good sig: %v", err)
	}

	// Tamper: flip a byte of the payload, expect verification failure.
	bad := append([]byte{}, enc...)
	bad[len(bad)-1] ^= 0x01
	if err := VerifyES256Raw(hwPub, sig, bad); err == nil {
		t.Fatal("verify tampered payload: want error, got nil")
	}

	// Decode round-trip.
	got, err := DecodeEncAuthPayload(enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sub != p.Sub || got.SID != p.SID || got.NotAfter != p.NotAfter {
		t.Fatalf("decoded mismatch: %+v", got)
	}
}

// TestEncAuthCanonicalDeterministic ensures two encodes of the same
// payload produce byte-identical bytes (so signatures stay stable
// regardless of map iteration order).
func TestEncAuthCanonicalDeterministic(t *testing.T) {
	p := &EncAuth{
		V: 1, Sub: "u", SID: "s",
		AppID: bytes32(1), EncMeas: bytes32(2),
		EncPub: sec1Pub(), QuoteHash: bytes32(3),
		NotBefore: 10, NotAfter: 20, HwPub: sec1Pub(),
	}
	a, _ := EncAuthCanonicalCBOR(p)
	b, _ := EncAuthCanonicalCBOR(p)
	if string(a) != string(b) {
		t.Fatalf("canonical encoding not deterministic")
	}
}

func bytes32(v byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = v
	}
	return out
}

func sec1Pub() []byte {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
}
