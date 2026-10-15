// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

//go:build cgo

package sessions

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(db)
	if err != nil {
		t.Fatalf("new sessions: %v", err)
	}
	// Every client in the shared sector, standing for no app: the store
	// refuses vouchers outright without a registry behind it.
	s.SetSectorResolver(func(string) string { return "" })
	s.SetAppsResolver(func(string) []string { return nil })
	s.SetPasskeysResolver(func(string) ([][]byte, error) { return testPasskeys.all(), nil })
	return s
}

// testPasskeys holds every key signedVoucher signs with: in these tests
// each is a passkey of the identity.
var testPasskeys passkeyList

type passkeyList struct {
	mu   sync.Mutex
	keys [][]byte
}

func (l *passkeyList) add(k []byte) { l.mu.Lock(); l.keys = append(l.keys, k); l.mu.Unlock() }
func (l *passkeyList) all() [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([][]byte(nil), l.keys...)
}

func TestCreateAndIsActive(t *testing.T) {
	s := newTestStore(t)
	row, err := s.Create("", "user-1", "client-a", "device-x", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if row.SID == "" {
		t.Fatal("SID empty")
	}
	if !s.IsActive(row.SID) {
		t.Fatal("expected active")
	}
}

func TestRevokeMakesInactive(t *testing.T) {
	s := newTestStore(t)
	row, err := s.Create("", "user-1", "client-a", "", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Revoke(row.SID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if s.IsActive(row.SID) {
		t.Fatal("expected inactive after revoke")
	}
	// Touch on a revoked session reports ErrRevoked.
	if err := s.Touch(row.SID, time.Hour); err != ErrRevoked {
		t.Fatalf("Touch revoked: got %v want ErrRevoked", err)
	}
}

func TestTouchExtends(t *testing.T) {
	s := newTestStore(t)
	row, err := s.Create("", "user-1", "client-a", "", time.Minute)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	original := row.ExpiresAt
	time.Sleep(5 * time.Millisecond)
	if err := s.Touch(row.SID, time.Hour); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, err := s.Get(row.SID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.ExpiresAt.After(original) {
		t.Fatalf("expires_at not extended: %v <= %v", got.ExpiresAt, original)
	}
}

func TestListByUser(t *testing.T) {
	s := newTestStore(t)
	a, _ := s.Create("", "user-1", "client-a", "", time.Hour)
	b, _ := s.Create("", "user-1", "client-b", "", time.Hour)
	_, _ = s.Create("", "user-2", "client-a", "", time.Hour)

	list, err := s.ListByUser("user-1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("len=%d want 2", len(list))
	}
	// Revoked rows are excluded.
	_ = s.Revoke(a.SID)
	list, _ = s.ListByUser("user-1")
	if len(list) != 1 || list[0].SID != b.SID {
		t.Fatalf("expected only b, got %#v", list)
	}
}

// TestMultiAppEncAuth verifies one session can hold a separate voucher per
// enclave (app_id), each retrievable by its app_id, with the no-selector read
// returning the most recent — the storage half of multi-app attestation.
func TestMultiAppEncAuth(t *testing.T) {
	s := newTestStore(t)
	iss, err := tokens.NewIssuer(filepath.Join(t.TempDir(), "key.pem"), "https://privasys.id")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	row, err := s.Create("", "user-1", "client-a", "", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	app1, app2 := bytes32(0x11), bytes32(0x22)
	hosts := map[byte]string{app1[0]: "a.example", app2[0]: "b.example"}
	for _, appID := range [][]byte{app1, app2} {
		payload, hwSig := signedVoucher(t, "user-1", row.SID, appID)
		if _, err := s.PutEncAuth("user-1", "", payload, hwSig, hosts[appID[0]], iss); err != nil {
			t.Fatalf("PutEncAuth(%x): %v", appID[0], err)
		}
	}

	// Each enclave's voucher is selectable by its app_id.
	for _, appID := range [][]byte{app1, app2} {
		env, err := s.GetEncAuth(row.SID, appID, "")
		if err != nil {
			t.Fatalf("GetEncAuth(app_id %x): %v", appID[0], err)
		}
		if got := voucherAppID(t, env); !bytes.Equal(got, appID) {
			t.Fatalf("voucher app_id = %x, want %x", got[0], appID[0])
		}
	}

	// ...and by host (the browser SDK's selector).
	for _, appID := range [][]byte{app1, app2} {
		env, err := s.GetEncAuth(row.SID, nil, hosts[appID[0]])
		if err != nil {
			t.Fatalf("GetEncAuth(host %s): %v", hosts[appID[0]], err)
		}
		if got := voucherAppID(t, env); !bytes.Equal(got, appID) {
			t.Fatalf("host %s returned app_id %x, want %x", hosts[appID[0]], got[0], appID[0])
		}
	}

	// No selector → the most recently stored voucher (app2).
	recent, err := s.GetEncAuth(row.SID, nil, "")
	if err != nil {
		t.Fatalf("GetEncAuth(no selector): %v", err)
	}
	if got := voucherAppID(t, recent); !bytes.Equal(got, app2) {
		t.Fatalf("no-selector returned app_id %x, want most-recent %x", got[0], app2[0])
	}

	// An unknown selector is not found (not silently the wrong voucher).
	if _, err := s.GetEncAuth(row.SID, bytes32(0x99), ""); err == nil {
		t.Fatal("GetEncAuth(unknown app_id): want ErrNotFound, got nil")
	}
	if _, err := s.GetEncAuth(row.SID, nil, "nope.example"); err == nil {
		t.Fatal("GetEncAuth(unknown host): want ErrNotFound, got nil")
	}
}

// signedVoucher builds a valid canonical EncAuth payload + hw_sig for tests.
func signedVoucher(t *testing.T, sub, sid string, appID []byte) (payload, hwSig []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hwPub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	testPasskeys.add(hwPub)
	now := uint64(time.Now().Unix())
	p := &EncAuth{
		V: 1, Sub: sub, SID: sid,
		WorkloadDigest: appID, EncMeas: bytes32(0xe0), EncPub: sec1Pub(),
		QuoteHash: bytes32(0xc0), NotBefore: now - 10, NotAfter: now + 3600,
		HwPub: hwPub,
	}
	payload, err = EncAuthCanonicalCBOR(p)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	r, ss, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	hwSig = make([]byte, 64)
	rb, sb := r.Bytes(), ss.Bytes()
	copy(hwSig[32-len(rb):32], rb)
	copy(hwSig[64-len(sb):], sb)
	return payload, hwSig
}

func voucherAppID(t *testing.T, env *Envelope) []byte {
	t.Helper()
	pb, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodeEncAuthPayload(pb)
	if err != nil {
		t.Fatal(err)
	}
	return p.WorkloadDigest
}

func TestNewSIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		sid := NewSID()
		if seen[sid] {
			t.Fatalf("duplicate SID: %s", sid)
		}
		seen[sid] = true
	}
}

// Removing a phone, or recovering the account, ends every sealed session of
// the account: they would otherwise rebind on their vouchers for 90 days.
func TestRevokeAllForUserEndsEverySessionAndRunsTheHook(t *testing.T) {
	s := newTestStore(t)
	var hooked []string
	s.SetRevokeHook(func(sid string) { hooked = append(hooked, sid) })
	a, _ := s.FindOrCreateForApp("alice", "app-1", "", time.Hour)
	b, _ := s.FindOrCreateForApp("alice", "app-2", "", time.Hour)
	c, _ := s.FindOrCreateForApp("bob", "app-1", "", time.Hour)
	n, err := s.RevokeAllForUser("alice")
	if err != nil || n != 2 {
		t.Fatalf("revoke all: n=%d err=%v", n, err)
	}
	if s.IsActive(a.SID) || s.IsActive(b.SID) {
		t.Fatal("alice's sessions still active")
	}
	if !s.IsActive(c.SID) {
		t.Fatal("bob's session ended")
	}
	if len(hooked) != 2 {
		t.Fatalf("hook ran for %v", hooked)
	}
	if n, _ := s.RevokeAllForUser("alice"); n != 0 {
		t.Fatalf("second pass ended %d", n)
	}
}
