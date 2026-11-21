package fido2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func vaultStatus(t *testing.T, h *Handler, challenge string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.VaultApprovalStatus()(rec, httptest.NewRequest(http.MethodGet,
		"/fido2/vault-approval/status?challenge="+url.QueryEscape(challenge), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body struct{ Status string }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Status
}

// The approval page follows one approval from pending to its outcome, and
// still sees the outcome after the initiator has collected the token.
func TestVaultApprovalStatus(t *testing.T) {
	h := newDeclineTestHandler()
	exp := time.Now().Add(time.Minute)

	if got := vaultStatus(t, h, "unknown"); got != "gone" {
		t.Fatalf("unknown approval: %q, want gone", got)
	}

	h.vaultPending.put("op1", &vaultPendingEntry{sub: "owner", expiresAt: exp})
	if got := vaultStatus(t, h, "op1"); got != "pending" {
		t.Fatalf("waiting approval: %q, want pending", got)
	}

	h.vaultResults.put("op1", "owner", "token", exp.Unix())
	h.vaultPending.remove("op1")
	if got := vaultStatus(t, h, "op1"); got != "approved" {
		t.Fatalf("approved: %q, want approved", got)
	}
	if _, ok := h.vaultResults.take("op1", "owner"); !ok {
		t.Fatal("the initiator could not collect the token")
	}
	if got := vaultStatus(t, h, "op1"); got != "approved" {
		t.Fatalf("after collection: %q, want approved", got)
	}

	h.vaultResults.decline("op2", "owner", exp)
	if got := vaultStatus(t, h, "op2"); got != "declined" {
		t.Fatalf("declined: %q, want declined", got)
	}

	h.vaultResults.put("op3", "owner", "token", time.Now().Add(-time.Second).Unix())
	if got := vaultStatus(t, h, "op3"); got != "gone" {
		t.Fatalf("expired: %q, want gone", got)
	}

	rec := httptest.NewRecorder()
	h.VaultApprovalStatus()(rec, httptest.NewRequest(http.MethodGet, "/fido2/vault-approval/status", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no challenge: %d, want 400", rec.Code)
	}
}
