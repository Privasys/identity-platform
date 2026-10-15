// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package fido2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// coseOf writes a P-256 public key as a COSE EC2 key, the way a passkey's
// key is stored.
func coseOf(t *testing.T, k *ecdsa.PublicKey) []byte {
	t.Helper()
	x, y := make([]byte, 32), make([]byte, 32)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)
	b, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSEC1OfAPasskey(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	got, err := SEC1Of(coseOf(t, &k.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if want := elliptic.Marshal(elliptic.P256(), k.X, k.Y); !bytes.Equal(got, want) {
		t.Fatalf("SEC1 %x, want %x", got, want)
	}
	if _, err := SEC1Of([]byte{0xa0}); err == nil {
		t.Fatal("an empty COSE map was read as a key")
	}
}
