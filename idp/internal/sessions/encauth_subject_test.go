// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessions

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

// The voucher's subject is what an enclave asserts as X-Privasys-Sub, so the
// IdP co-signs only the subject the session's client sees: the account id in
// the shared sector, the client's own subject otherwise.
func TestTheVoucherCarriesTheClientsSubject(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	iss, err := tokens.NewIssuer(filepath.Join(dir, "k.pem"), "https://privasys.id")
	if err != nil {
		t.Fatal(err)
	}
	iss.SetSubjectStore(db)
	if _, err := db.Exec("INSERT INTO users (user_id) VALUES ('acct-1')"); err != nil {
		t.Fatal(err)
	}
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	sectors := map[string]string{"site": "site", "privasys-platform": ""}
	s.SetSectorResolver(func(c string) string { return sectors[c] })

	hw, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hwPub := elliptic.Marshal(elliptic.P256(), hw.PublicKey.X, hw.PublicKey.Y)
	put := func(client, sub string) error {
		sess, err := s.FindOrCreateForApp("acct-1", client, "", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		now := uint64(time.Now().Unix())
		payload, err := EncAuthCanonicalCBOR(&EncAuth{
			V: 1, Sub: sub, SID: sess.SID,
			WorkloadDigest: bytes32(1), EncMeas: bytes32(2), EncPub: sec1Pub(), QuoteHash: bytes32(3),
			NotBefore: now - 10, NotAfter: now + 3600, HwPub: hwPub,
		})
		if err != nil {
			t.Fatal(err)
		}
		d := sha256.Sum256(payload)
		r, sv, _ := ecdsa.Sign(rand.Reader, hw, d[:])
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		sv.FillBytes(sig[32:])
		_, err = s.PutEncAuth("acct-1", payload, sig, "app.example", iss)
		return err
	}

	siteSub := iss.SubjectFor("acct-1", "site")
	if err := put("site", "acct-1"); err == nil || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("a voucher naming the account to an own-sector client: %v, want refused", err)
	}
	if err := put("site", siteSub); err != nil {
		t.Fatalf("a voucher with the client's subject: %v", err)
	}
	if err := put("privasys-platform", "acct-1"); err != nil {
		t.Fatalf("a shared-sector voucher with the account id: %v", err)
	}
	if err := put("privasys-platform", siteSub); err == nil {
		t.Fatal("a shared-sector voucher accepted another sector's subject")
	}
}
