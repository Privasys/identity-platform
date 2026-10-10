// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Privasys/idp/internal/store"
)

const (
	tagA = "phoneAphoneAphoneAphon"
	tagB = "phoneBphoneBphoneBphon"
)

func devicesTestHandler(t *testing.T) (*Handler, *store.DB, *http.ServeMux) {
	t.Helper()
	h, db, mux := identityTestHandler(t)
	mux.HandleFunc("POST /devices/enrol-ticket", h.HandleEnrolTicket)
	mux.HandleFunc("POST /devices/enrol", h.HandleRedeemEnrolTicket)
	mux.HandleFunc("POST /devices/revoke", h.HandleRevokePhone)
	mux.HandleFunc("POST /devices/pair", h.HandleOpenPairing)
	mux.HandleFunc("PUT /devices/pair/{slot}", h.HandleFillPairing)
	mux.HandleFunc("GET /devices/pair/{slot}", h.HandleReadPairing)
	mux.HandleFunc("POST /devices/relay", h.HandlePostRelay)
	mux.HandleFunc("GET /devices/relay", h.HandleGetRelay)
	mux.HandleFunc("POST /recovery/identity/enrol", h.HandleEnrolIdentity)
	mux.HandleFunc("POST /recovery/identity/revoke-device", h.HandleRevokeIdentityDevice)
	mux.HandleFunc("PUT /recovery/identity-index", h.HandlePutIdentityIndex)
	mux.HandleFunc("GET /recovery/identity-index", h.HandleGetIdentityIndex)
	return h, db, mux
}

func addCredential(t *testing.T, db *store.DB, user, id, tag string) {
	t.Helper()
	if _, err := db.Exec("INSERT INTO credentials (credential_id, user_id, public_key, device_tag) VALUES (?, ?, x'00', ?)", id, user, tag); err != nil {
		t.Fatalf("insert credential: %v", err)
	}
}

func credentials(t *testing.T, db *store.DB, user string) []string {
	t.Helper()
	rows, err := db.Query("SELECT credential_id FROM credentials WHERE user_id = ? ORDER BY credential_id", user)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		out = append(out, id)
	}
	return out
}

func enrolGranted(t *testing.T, db *store.DB, user string) bool {
	t.Helper()
	var n int
	db.QueryRow("SELECT COUNT(*) FROM recovery_requests WHERE user_id = ? AND status = 'enrol'", user).Scan(&n)
	return n > 0
}

func TestEnrolTicketOpensTheAccountWithoutRemovingPasskeys(t *testing.T) {
	_, db, mux := devicesTestHandler(t)
	addCredential(t, db, "bob", "cred-a", tagA)

	rec := call(mux, "POST", "/devices/enrol-ticket", "", "wallet:bob")
	if rec.Code != http.StatusOK {
		t.Fatalf("ticket: %d %s", rec.Code, rec.Body)
	}
	var tk struct{ Ticket string }
	json.Unmarshal(rec.Body.Bytes(), &tk)

	if rec := call(mux, "POST", "/devices/enrol", `{"ticket":"`+tk.Ticket+`"}`, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"bob"`) {
		t.Fatalf("redeem: %d %s", rec.Code, rec.Body)
	}
	if !enrolGranted(t, db, "bob") {
		t.Fatal("no enrolment granted")
	}
	if got := credentials(t, db, "bob"); len(got) != 1 {
		t.Fatalf("enrolment removed passkeys: %v", got)
	}
	if rec := call(mux, "POST", "/devices/enrol", `{"ticket":"`+tk.Ticket+`"}`, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("a ticket works twice: %d", rec.Code)
	}
}

func TestIdentityEnrolNeedsTheRecoveryKey(t *testing.T) {
	_, db, mux := devicesTestHandler(t)
	key := keyFor(1)
	setKey(t, mux, "alice-drive", key)
	addCredential(t, db, "alice-drive", "cred-a", tagA)

	_, c := begin(t, mux, "alice-drive")
	bad := ed25519.Sign(keyFor(2), IdentityEnrolMessage("alice-drive", c))
	rec := call(mux, "POST", "/recovery/identity/enrol", `{"user_id":"alice-drive","challenge":"`+b64(c)+`","signature":"`+b64(bad)+`"}`, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong key: %d", rec.Code)
	}

	_, c = begin(t, mux, "alice-drive")
	// A recovery signature is not an enrolment signature.
	wrongDomain := ed25519.Sign(key, IdentityRecoveryMessage("alice-drive", c))
	rec = call(mux, "POST", "/recovery/identity/enrol", `{"user_id":"alice-drive","challenge":"`+b64(c)+`","signature":"`+b64(wrongDomain)+`"}`, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("recovery signature accepted for enrolment: %d", rec.Code)
	}

	_, c = begin(t, mux, "alice-drive")
	sig := ed25519.Sign(key, IdentityEnrolMessage("alice-drive", c))
	rec = call(mux, "POST", "/recovery/identity/enrol", `{"user_id":"alice-drive","challenge":"`+b64(c)+`","signature":"`+b64(sig)+`"}`, "")
	if rec.Code != http.StatusOK || !enrolGranted(t, db, "alice-drive") {
		t.Fatalf("enrol: %d %s", rec.Code, rec.Body)
	}
	if got := credentials(t, db, "alice-drive"); len(got) != 1 {
		t.Fatalf("enrolment removed passkeys: %v", got)
	}
}

func TestRevokeIdentityDeviceRotatesTheKey(t *testing.T) {
	_, db, mux := devicesTestHandler(t)
	old := keyFor(1)
	setKey(t, mux, "alice-drive", old)
	addCredential(t, db, "alice-drive", "cred-a", tagA)
	addCredential(t, db, "alice-drive", "cred-b", tagB)
	addCredential(t, db, "alice-drive", "cred-legacy", "")
	db.UpsertDevicePushTarget("alice-drive", tagA, "tokA", "")
	db.UpsertDevicePushTarget("alice-drive", tagB, "tokB", "")

	newKey := keyFor(9)
	newPub := b64(newKey.Public().(ed25519.PublicKey))
	revoke := func(signer ed25519.PrivateKey) *string {
		_, c := begin(t, mux, "alice-drive")
		sig := ed25519.Sign(signer, IdentityRevokeMessage("alice-drive", c, tagB, newPub))
		rec := call(mux, "POST", "/recovery/identity/revoke-device",
			`{"user_id":"alice-drive","device_tag":"`+tagB+`","keep_credential_id":"cred-a","new_public_key":"`+newPub+`","challenge":"`+b64(c)+`","signature":"`+b64(sig)+`"}`, "")
		s := rec.Body.String()
		if rec.Code != http.StatusOK {
			s = "status " + http.StatusText(rec.Code)
		}
		return &s
	}
	if got := revoke(old); !strings.Contains(*got, `"rotated":true`) {
		t.Fatalf("revoke: %s", *got)
	}
	if got := credentials(t, db, "alice-drive"); len(got) != 1 || got[0] != "cred-a" {
		t.Fatalf("after revoke: %v (want only cred-a: phone B and the untagged passkey go)", got)
	}
	if got := db.GetPushTokens("alice-drive"); len(got) != 1 || got[0] != "tokA" {
		t.Fatalf("push targets after revoke: %v", got)
	}
	// Phone B still holds the old key: it can no longer act on the identity.
	if got := revoke(old); !strings.Contains(*got, "Forbidden") {
		t.Fatalf("the revoked phone's key still works: %s", *got)
	}
	_, c := begin(t, mux, "alice-drive")
	if rec := complete(mux, "alice-drive", c, ed25519.Sign(old, IdentityRecoveryMessage("alice-drive", c))); rec.Code != http.StatusForbidden {
		t.Fatalf("the revoked phone can still recover the identity: %d", rec.Code)
	}
}

func TestRevokePhoneKeepsTheCallersPasskey(t *testing.T) {
	h, db, mux := devicesTestHandler(t)
	h.SetSessionCredential(func(string) string { return "cred-a" })
	var ended []string
	h.SetWalletSessionEnder(func(ids []string) { ended = append(ended, ids...) })
	addCredential(t, db, "bob", "cred-a", "")
	addCredential(t, db, "bob", "cred-b", tagB)

	rec := call(mux, "POST", "/devices/revoke", `{"device_tag":"`+tagB+`"}`, "wallet:bob")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	if got := credentials(t, db, "bob"); len(got) != 1 || got[0] != "cred-a" {
		t.Fatalf("after revoke: %v", got)
	}
	if len(ended) != 1 || ended[0] != "cred-b" {
		t.Fatalf("sessions ended for %v", ended)
	}
}

func TestPairingSlotIsReadOnce(t *testing.T) {
	_, _, mux := devicesTestHandler(t)
	key := b64(make([]byte, 32))
	rec := call(mux, "POST", "/devices/pair", `{"public_key":"`+key+`"}`, "")
	var p struct{ Slot string }
	json.Unmarshal(rec.Body.Bytes(), &p)
	if p.Slot == "" {
		t.Fatalf("open: %d %s", rec.Code, rec.Body)
	}
	if rec := call(mux, "GET", "/devices/pair/"+p.Slot, "", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("empty slot: %d", rec.Code)
	}
	if rec := call(mux, "PUT", "/devices/pair/"+p.Slot, `{"sender_public_key":"`+key+`","blob":"c2VhbGVk"}`, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a slot filled without a session: %d", rec.Code)
	}
	if rec := call(mux, "PUT", "/devices/pair/"+p.Slot, `{"sender_public_key":"`+key+`","blob":"c2VhbGVk"}`, "wallet:bob"); rec.Code != http.StatusOK {
		t.Fatalf("fill: %d %s", rec.Code, rec.Body)
	}
	if rec := call(mux, "PUT", "/devices/pair/"+p.Slot, `{"sender_public_key":"`+key+`","blob":"b3RoZXI"}`, "wallet:bob"); rec.Code != http.StatusConflict {
		t.Fatalf("refill: %d", rec.Code)
	}
	if rec := call(mux, "GET", "/devices/pair/"+p.Slot, "", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "c2VhbGVk") {
		t.Fatalf("read: %d %s", rec.Code, rec.Body)
	}
	if rec := call(mux, "GET", "/devices/pair/"+p.Slot, "", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("read twice: %d", rec.Code)
	}
}

func TestRelayHandsOverOnce(t *testing.T) {
	_, _, mux := devicesTestHandler(t)
	if rec := call(mux, "POST", "/devices/relay", `{"items":[{"to":"`+tagB+`","blob":"dXBkYXRl","wake":{"account":"bob","tag":"`+tagB+`"}}]}`, ""); rec.Code != http.StatusOK {
		t.Fatalf("post: %d %s", rec.Code, rec.Body)
	}
	if rec := call(mux, "GET", "/devices/relay?to="+tagA, "", ""); strings.Contains(rec.Body.String(), "dXBkYXRl") {
		t.Fatal("handed to another address")
	}
	rec := call(mux, "GET", "/devices/relay?to="+tagB, "", "")
	if !strings.Contains(rec.Body.String(), "dXBkYXRl") {
		t.Fatalf("get: %s", rec.Body)
	}
	if rec := call(mux, "GET", "/devices/relay?to="+tagB, "", ""); strings.Contains(rec.Body.String(), "dXBkYXRl") {
		t.Fatal("relay handed the same update twice")
	}
}

func TestSelfRemovalLeavesUntaggedPasskeys(t *testing.T) {
	_, db, _ := devicesTestHandler(t)
	addCredential(t, db, "bob", "mine", tagA)
	addCredential(t, db, "bob", "old-phone", "")
	ids, err := db.RevokeDevice("bob", tagA, store.KeepAllUntagged)
	if err != nil || len(ids) != 1 || ids[0] != "mine" {
		t.Fatalf("removed %v (%v)", ids, err)
	}
	if got := credentials(t, db, "bob"); len(got) != 1 || got[0] != "old-phone" {
		t.Fatalf("left %v", got)
	}
}

func TestIdentityIndexRefusesAStaleWrite(t *testing.T) {
	_, _, mux := devicesTestHandler(t)
	if rec := call(mux, "PUT", "/recovery/identity-index", `{"blob":"djE","version":0}`, "wallet:bob"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"version":1`) {
		t.Fatalf("first write: %d %s", rec.Code, rec.Body)
	}
	if rec := call(mux, "PUT", "/recovery/identity-index", `{"blob":"djI","version":0}`, "wallet:bob"); rec.Code != http.StatusConflict {
		t.Fatalf("stale write: %d %s", rec.Code, rec.Body)
	}
	if rec := call(mux, "PUT", "/recovery/identity-index", `{"blob":"djI","version":1}`, "wallet:bob"); rec.Code != http.StatusOK {
		t.Fatalf("current write: %d %s", rec.Code, rec.Body)
	}
	// A wallet from before devices sends no version and still writes.
	if rec := call(mux, "PUT", "/recovery/identity-index", `{"blob":"djM"}`, "wallet:bob"); rec.Code != http.StatusOK {
		t.Fatalf("unversioned write: %d %s", rec.Code, rec.Body)
	}
	if rec := call(mux, "GET", "/recovery/identity-index", "", "wallet:bob"); !strings.Contains(rec.Body.String(), `"version":3`) {
		t.Fatalf("get: %s", rec.Body)
	}
}

func TestDeviceLimit(t *testing.T) {
	_, db, _ := devicesTestHandler(t)
	for i, tag := range []string{"t1t1t1t1t1t1t1t1", "t2t2t2t2t2t2t2t2", "t3t3t3t3t3t3t3t3", "t4t4t4t4t4t4t4t4", "t5t5t5t5t5t5t5t5"} {
		addCredential(t, db, "bob", "c"+string(rune('0'+i)), tag)
	}
	if full, _ := db.DeviceLimitReached("bob", "t6t6t6t6t6t6t6t6"); !full {
		t.Fatal("a sixth phone was allowed")
	}
	if full, _ := db.DeviceLimitReached("bob", "t3t3t3t3t3t3t3t3"); full {
		t.Fatal("a phone already there was refused")
	}
}

func TestRevokeAllOtherPhones(t *testing.T) {
	_, db, mux := devicesTestHandler(t)
	key := keyFor(3)
	setKey(t, mux, "alice-ai", key)
	addCredential(t, db, "alice-ai", "lost-tagged", tagB)
	addCredential(t, db, "alice-ai", "lost-untagged", "")
	db.UpsertDevicePushTarget("alice-ai", tagB, "tokB", "")
	_, c := begin(t, mux, "alice-ai")
	sig := ed25519.Sign(key, IdentityRevokeMessage("alice-ai", c, "*", ""))
	rec := call(mux, "POST", "/recovery/identity/revoke-device",
		`{"user_id":"alice-ai","device_tag":"*","keep_credential_id":"","new_public_key":"","challenge":"`+b64(c)+`","signature":"`+b64(sig)+`"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke all: %d %s", rec.Code, rec.Body)
	}
	if got := credentials(t, db, "alice-ai"); len(got) != 0 {
		t.Fatalf("left %v", got)
	}
	if got := db.GetPushTokens("alice-ai"); len(got) != 0 {
		t.Fatalf("push targets left %v", got)
	}
}

// The wallet signs exactly these bytes (wallet/src/__tests__/devices.test.ts
// builds the same ones).
func TestDeviceMessagesMatchTheWallet(t *testing.T) {
	c := []byte{1, 2, 3, 4}
	if got := hex.EncodeToString(IdentityEnrolMessage("user-1", c)); got != "70726976617379732d6964656e746974792d656e726f6c2f763100757365722d310001020304" {
		t.Fatalf("enrol message: %s", got)
	}
	if got := hex.EncodeToString(IdentityRevokeMessage("user-1", c, "tag", "newpub")); got != "70726976617379732d6964656e746974792d7265766f6b652f763100757365722d31000102030400746167006e6577707562" {
		t.Fatalf("revoke message: %s", got)
	}
}
