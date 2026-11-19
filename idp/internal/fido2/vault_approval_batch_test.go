// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package fido2

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	digestA = "1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "2222222222222222222222222222222222222222222222222222222222222222"
)

func batchEntries() []vaultBatchEntry {
	return []vaultBatchEntry{
		{Operation: "promote", Handle: "apps.privasys.org/bbbb/storage-kek/v1", MeasurementDigest: digestB, PolicyVersion: 7},
		{Operation: "app-policy", Handle: "app:aaaa:policy", MeasurementDigest: digestA, PolicyVersion: 3},
		{Operation: "promote", Handle: "apps.privasys.org/bbbb/registry-cred/default", MeasurementDigest: digestA, PolicyVersion: 2},
	}
}

func fixedNonces() func() (string, error) {
	i := 0
	return func() (string, error) {
		i++
		return fmt.Sprintf("nonce-%d", i), nil
	}
}

func TestBatchOrderDoesNotDependOnTheRequest(t *testing.T) {
	a, err := validateVaultBatch("Runtime", batchEntries())
	if err != nil {
		t.Fatal(err)
	}
	rev := batchEntries()
	rev[0], rev[2] = rev[2], rev[0]
	b, err := validateVaultBatch("Runtime", rev)
	if err != nil {
		t.Fatal(err)
	}
	idA, _, _ := bindVaultBatch("Runtime", 1000, a, fixedNonces())
	idB, _, _ := bindVaultBatch("Runtime", 1000, b, fixedNonces())
	if idA != idB {
		t.Fatalf("the same list bound differently: %s, %s", idA, idB)
	}
	if a[0].Handle != "app:aaaa:policy" {
		t.Fatalf("not sorted by handle: %s", a[0].Handle)
	}
}

func TestBatchRefusals(t *testing.T) {
	many := make([]vaultBatchEntry, vaultBatchMaxEntries+1)
	for i := range many {
		many[i] = vaultBatchEntry{Operation: "promote", Handle: fmt.Sprintf("h/%d", i), MeasurementDigest: digestA}
	}
	ok := vaultBatchEntry{Operation: "promote", Handle: "h/1", MeasurementDigest: digestA}
	cases := []struct {
		name    string
		label   string
		entries []vaultBatchEntry
	}{
		{"no label", "", []vaultBatchEntry{ok}},
		{"newline in label", "a\nb", []vaultBatchEntry{ok}},
		{"long label", strings.Repeat("a", vaultBatchMaxLabelRunes+1), []vaultBatchEntry{ok}},
		{"bidi override in label", "Runtime " + string(rune(0x202e)) + "1.0", []vaultBatchEntry{ok}},
		{"zero width in label", "Run" + string(rune(0x200b)) + "time", []vaultBatchEntry{ok}},
		{"soft hyphen in label", "Run" + string(rune(0x00ad)) + "time", []vaultBatchEntry{ok}},
		{"line separator in label", "Run" + string(rune(0x2028)) + "time", []vaultBatchEntry{ok}},
		{"byte order mark in label", "Run" + string(rune(0xfeff)) + "time", []vaultBatchEntry{ok}},
		{"bidi mark in handle", "L", []vaultBatchEntry{{Operation: "promote", Handle: "h/" + string(rune(0x200f)) + "1", MeasurementDigest: digestA}}},
		{"wide space in handle", "L", []vaultBatchEntry{{Operation: "promote", Handle: "h/" + string(rune(0x3000)) + "1", MeasurementDigest: digestA}}},
		{"invalid text in handle", "L", []vaultBatchEntry{{Operation: "promote", Handle: "h/\xff", MeasurementDigest: digestA}}},
		{"empty", "L", nil},
		{"too many", "L", many},
		{"export", "L", []vaultBatchEntry{{Operation: "export", Handle: "h/1", MeasurementDigest: digestA}}},
		{"policy update", "L", []vaultBatchEntry{{Operation: "policy-update", Handle: "h/1", MeasurementDigest: digestA}}},
		{"recovery", "L", []vaultBatchEntry{{Operation: "app-recovery", Handle: "app:a:recover:1", MeasurementDigest: digestA}}},
		{"default operation", "L", []vaultBatchEntry{{Handle: "h/1", MeasurementDigest: digestA}}},
		{"newline in handle", "L", []vaultBatchEntry{{Operation: "promote", Handle: "h\n1", MeasurementDigest: digestA}}},
		{"space in handle", "L", []vaultBatchEntry{{Operation: "promote", Handle: "h 1", MeasurementDigest: digestA}}},
		{"bad digest", "L", []vaultBatchEntry{{Operation: "promote", Handle: "h/1", MeasurementDigest: "ABC"}}},
		{"uppercase digest", "L", []vaultBatchEntry{{Operation: "promote", Handle: "h/1", MeasurementDigest: strings.ToUpper("a" + digestA[1:])}}},
		{"policy handle", "L", []vaultBatchEntry{{Operation: "app-policy", Handle: "h/1", MeasurementDigest: digestA}}},
		{"duplicate", "L", []vaultBatchEntry{ok, ok}},
	}
	for _, c := range cases {
		if _, err := validateVaultBatch(c.label, c.entries); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

// Every value the owner relies on moves the binding.
func TestBatchBindingCoversTheList(t *testing.T) {
	base, err := validateVaultBatch("Runtime", batchEntries())
	if err != nil {
		t.Fatal(err)
	}
	id, _, _ := bindVaultBatch("Runtime", 1000, base, fixedNonces())

	mutate := map[string]func(e []vaultBatchEntry) (string, int64){
		"label":       func(e []vaultBatchEntry) (string, int64) { return "Other", 1000 },
		"expiry":      func(e []vaultBatchEntry) (string, int64) { return "Runtime", 1001 },
		"handle":      func(e []vaultBatchEntry) (string, int64) { e[1].Handle += "x"; return "Runtime", 1000 },
		"measurement": func(e []vaultBatchEntry) (string, int64) { e[1].MeasurementDigest = digestB; return "Runtime", 1000 },
		"version":     func(e []vaultBatchEntry) (string, int64) { e[1].PolicyVersion++; return "Runtime", 1000 },
	}
	for name, m := range mutate {
		e, _ := validateVaultBatch("Runtime", batchEntries())
		label, exp := m(e)
		got, _, _ := bindVaultBatch(label, exp, e, fixedNonces())
		if got == id {
			t.Errorf("%s does not move the binding", name)
		}
	}
	// Dropping an entry, and relabelling an operation.
	e, _ := validateVaultBatch("Runtime", batchEntries())
	short := e[:2]
	if got, _, _ := bindVaultBatch("Runtime", 1000, short, fixedNonces()); got == id {
		t.Error("dropping an entry does not move the binding")
	}
	e, _ = validateVaultBatch("Runtime", batchEntries())
	_, _, _ = bindVaultBatch("Runtime", 1000, e, fixedNonces())
	e[2].Operation = "export"
	sum := computeVaultBatchBinding("Runtime", 1000, e)
	if base64.RawURLEncoding.EncodeToString(sum[:]) == id {
		t.Error("the operation is not bound")
	}
}

// An entry's vault_op is the value the vault recomputes for a single promote.
func TestBatchEntryUsesTheVaultBinding(t *testing.T) {
	e, _ := validateVaultBatch("Runtime", batchEntries())
	if _, _, err := bindVaultBatch("Runtime", 1000, e, fixedNonces()); err != nil {
		t.Fatal(err)
	}
	for _, x := range e {
		sum := computeVaultApprovalBinding(x.Handle, x.MeasurementDigest, x.PolicyVersion, x.Nonce, 1000)
		if x.VaultOp != base64.RawURLEncoding.EncodeToString(sum[:]) {
			t.Fatalf("%s: vault_op differs from the single-operation binding", x.Handle)
		}
	}
}

func TestBatchStoreKeepsOneOpenBatchAndHandsTokensOutOnce(t *testing.T) {
	s := &vaultBatchStore{pending: map[string]*vaultBatchPending{}, open: map[string]string{}, results: map[string]vaultBatchResult{}}
	exp := time.Now().Add(time.Minute)
	s.put("one", &vaultBatchPending{sub: "owner", expiresAt: exp})
	if replaced := s.put("two", &vaultBatchPending{sub: "owner", expiresAt: exp}); replaced != "one" {
		t.Fatalf("replaced %q", replaced)
	}
	if _, ok := s.get("one"); ok {
		t.Fatal("the replaced batch is still open")
	}
	s.finish("two", "owner", []vaultBatchToken{{Handle: "h"}}, exp.Unix())
	if _, ok := s.get("two"); ok {
		t.Fatal("a finished batch is still open")
	}
	if _, ok := s.take("two", "someone-else"); ok {
		t.Fatal("another subject collected the tokens")
	}
	if got, ok := s.take("two", "owner"); !ok || got.declined || len(got.tokens) != 1 {
		t.Fatal("the owner could not collect the tokens")
	}
	if _, ok := s.take("two", "owner"); ok {
		t.Fatal("the tokens were collected twice")
	}
}

func newDeclineTestHandler() *Handler {
	return &Handler{
		challenges:   &challengeStore{challenges: map[string]*challengeEntry{}},
		vaultBatches: &vaultBatchStore{pending: map[string]*vaultBatchPending{}, open: map[string]string{}, results: map[string]vaultBatchResult{}},
		vaultPending: &vaultPendingStore{pending: map[string]*vaultPendingEntry{}},
		vaultResults: &vaultResultStore{results: map[string]vaultResultEntry{}},
	}
}

func declineStatus(t *testing.T, hf http.HandlerFunc, path, challenge string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	hf(rec, httptest.NewRequest(http.MethodPost, path+"?challenge="+url.QueryEscape(challenge), nil))
	return rec.Code
}

// A declined batch leaves the phone's list, cannot be approved afterwards, and
// ends the initiator's poll with a refusal rather than a timeout.
func TestBatchDecline(t *testing.T) {
	h := newDeclineTestHandler()
	exp := time.Now().Add(time.Minute)
	h.challenges.put("batch-1", &challengeEntry{expiresAt: exp, vaultBatch: &vaultBatchMeta{sub: "owner", batchID: "batch-1"}})
	h.vaultBatches.put("batch-1", &vaultBatchPending{sub: "owner", expiresAt: exp})
	// A challenge of another kind under the same key is never consumed.
	h.challenges.put("other", &challengeEntry{expiresAt: exp})

	if got := declineStatus(t, h.VaultApprovalBatchDecline(), "/fido2/vault-approval/batch/decline", "other"); got != http.StatusNotFound {
		t.Fatalf("declining another kind of challenge: %d", got)
	}
	if _, ok := h.challenges.pop("other"); !ok {
		t.Fatal("the other challenge was consumed")
	}
	if got := declineStatus(t, h.VaultApprovalBatchDecline(), "/fido2/vault-approval/batch/decline", "batch-1"); got != http.StatusNoContent {
		t.Fatalf("decline: %d", got)
	}
	if _, ok := h.vaultBatches.get("batch-1"); ok {
		t.Fatal("the declined batch is still pending")
	}
	if _, ok := h.challenges.pop("batch-1"); ok {
		t.Fatal("the declined batch can still be approved")
	}
	if got := declineStatus(t, h.VaultApprovalBatchDecline(), "/fido2/vault-approval/batch/decline", "batch-1"); got != http.StatusNotFound {
		t.Fatalf("second decline: %d", got)
	}
	if _, ok := h.vaultBatches.take("batch-1", "someone-else"); ok {
		t.Fatal("another subject read the refusal")
	}
	if r, ok := h.vaultBatches.take("batch-1", "owner"); !ok || !r.declined || len(r.tokens) != 0 {
		t.Fatalf("the owner did not get the refusal: %+v %v", r, ok)
	}
}

func TestSingleDecline(t *testing.T) {
	h := newDeclineTestHandler()
	exp := time.Now().Add(time.Minute)
	op := "vault-op-1"
	h.challenges.put(op, &challengeEntry{expiresAt: exp, vaultApproval: &vaultApprovalMeta{sub: "owner", vaultOp: op, exp: exp.Unix()}})
	h.vaultPending.put(op, &vaultPendingEntry{sub: "owner", expiresAt: exp})

	if got := declineStatus(t, h.VaultApprovalDecline(), "/fido2/vault-approval/decline", op); got != http.StatusNoContent {
		t.Fatalf("decline: %d", got)
	}
	if _, ok := h.vaultPending.get(op); ok {
		t.Fatal("the declined approval is still pending")
	}
	if _, ok := h.challenges.pop(op); ok {
		t.Fatal("the declined approval can still be completed")
	}
	if got := declineStatus(t, h.VaultApprovalDecline(), "/fido2/vault-approval/decline", op); got != http.StatusNotFound {
		t.Fatalf("second decline: %d", got)
	}
	if r, ok := h.vaultResults.take(op, "owner"); !ok || !r.declined || r.token != "" {
		t.Fatalf("the owner did not get the refusal: %+v %v", r, ok)
	}
}

// The vectors every client must reproduce. Regenerate with
// WRITE_BATCH_VECTORS=<path> go test -run TestBatchVectors.
func TestBatchVectors(t *testing.T) {
	const label, exp = "Runtime tdx-v0.2.125 on m1-tdx-france", int64(1795000000)
	e, err := validateVaultBatch(label, batchEntries())
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := bindVaultBatch(label, exp, e, fixedNonces())
	if err != nil {
		t.Fatal(err)
	}
	const want = "fMYR8ksLNFmyC92yHO12RYqjR-ujjoRUYaX0bWLwOQk"
	if path := os.Getenv("WRITE_BATCH_VECTORS"); path != "" {
		out, _ := json.MarshalIndent(map[string]interface{}{
			"comment":       "Test vector for the vault approval batch binding. Generated by idp/internal/fido2/vault_approval_batch_test.go.",
			"domain":        vaultBatchDomain,
			"single_domain": vaultApprovalDomain,
			"label":         label,
			"exp":           exp,
			"entries":       e,
			"batch_id":      id,
		}, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if id != want {
		t.Fatalf("batch binding moved: %s", id)
	}
}
