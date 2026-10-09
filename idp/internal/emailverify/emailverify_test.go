// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package emailverify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Privasys/idp/internal/tokens"
)

type sentMail struct{ to, subject, body string }

type fakeMailer struct {
	sent    []sentMail
	enabled bool
	err     error
}

func (m *fakeMailer) Enabled() bool { return m.enabled }
func (m *fakeMailer) SendHTML(to, subject, body string) error {
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, sentMail{to, subject, body})
	return nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestIssuer(t *testing.T) *tokens.Issuer {
	t.Helper()
	iss, err := tokens.NewIssuer(filepath.Join(t.TempDir(), "key.pem"), "https://privasys.id")
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return iss
}

// harness wires the service behind a mux with a bearer that is the user id.
func harness(t *testing.T, m *fakeMailer, c *clock) (*http.ServeMux, *Service) {
	t.Helper()
	auth := func(w http.ResponseWriter, r *http.Request) string {
		sub := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if sub == "" {
			http.Error(w, "no", http.StatusUnauthorized)
		}
		return sub
	}
	s := newService(m, newTestIssuer(t), auth, c.now)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /wallet/email/verify/begin", s.HandleBegin)
	mux.HandleFunc("POST /wallet/email/verify/complete", s.HandleComplete)
	return mux, s
}

func post(mux *http.ServeMux, path, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// codeFrom reads the code out of the mail body the fake mailer captured.
func codeFrom(t *testing.T, m *fakeMailer) string {
	t.Helper()
	if len(m.sent) == 0 {
		t.Fatal("no mail was sent")
	}
	// The code is the one run of exactly six digits in the markup.
	found := regexp.MustCompile(`(^|[^0-9])([0-9]{6})([^0-9]|$)`).FindAllStringSubmatch(m.sent[len(m.sent)-1].body, -1)
	if len(found) == 1 {
		return found[0][2]
	}
	t.Fatalf("no 6-digit code in %q", m.sent[len(m.sent)-1].body)
	return ""
}

func TestTheCodeGoesToTheAddressAndTheReceiptSaysSo(t *testing.T) {
	m := &fakeMailer{enabled: true}
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	mux, _ := harness(t, m, c)

	if rec := post(mux, "/wallet/email/verify/begin", "alice", `{"email":"  Alice@Example.COM "}`); rec.Code != 200 {
		t.Fatalf("begin: %d %s", rec.Code, rec.Body)
	}
	if len(m.sent) != 1 || m.sent[0].to != "alice@example.com" {
		t.Fatalf("mail went to %+v", m.sent)
	}
	code := codeFrom(t, m)

	// The same address, however the holder capitalises it the second time.
	rec := post(mux, "/wallet/email/verify/complete", "alice", `{"email":"ALICE@example.com","code":"`+code+`"}`)
	if rec.Code != 200 {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body)
	}
	var body struct {
		Email, Receipt, Method string
		VerifiedAt             int64 `json:"verified_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Email != "alice@example.com" || body.Method != "email-code" || body.VerifiedAt != c.t.Unix() {
		t.Fatalf("body: %+v", body)
	}
	tok, _, err := jwt.NewParser().ParseUnverified(body.Receipt, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["sub"] != "alice" || claims["email"] != "alice@example.com" || claims["email_verified"] != true {
		t.Fatalf("receipt claims: %+v", claims)
	}
	if tok.Header["typ"] != "email-verification+jwt" {
		t.Fatalf("receipt typ: %v", tok.Header["typ"])
	}

	// Single use: the same code again is gone, not accepted twice.
	if rec := post(mux, "/wallet/email/verify/complete", "alice", `{"email":"alice@example.com","code":"`+code+`"}`); rec.Code != http.StatusGone {
		t.Fatalf("replay: %d, want 410", rec.Code)
	}
}

func TestAnotherAccountsCodeIsWorthless(t *testing.T) {
	m := &fakeMailer{enabled: true}
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	mux, _ := harness(t, m, c)

	post(mux, "/wallet/email/verify/begin", "alice", `{"email":"shared@example.com"}`)
	code := codeFrom(t, m)
	if rec := post(mux, "/wallet/email/verify/complete", "bob", `{"email":"shared@example.com","code":"`+code+`"}`); rec.Code != http.StatusGone {
		t.Fatalf("bob used alice's code: %d %s", rec.Code, rec.Body)
	}
}

func TestWrongCodesRunOutAndTheCodeDies(t *testing.T) {
	m := &fakeMailer{enabled: true}
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	mux, _ := harness(t, m, c)
	post(mux, "/wallet/email/verify/begin", "alice", `{"email":"alice@example.com"}`)
	right := codeFrom(t, m)
	wrong := "000000"
	if wrong == right {
		wrong = "111111"
	}

	for i := 1; i < maxAttempts; i++ {
		rec := post(mux, "/wallet/email/verify/complete", "alice", `{"email":"alice@example.com","code":"`+wrong+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: %d %s", i, rec.Code, rec.Body)
		}
		var body struct {
			AttemptsLeft int `json:"attempts_left"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body.AttemptsLeft != maxAttempts-i {
			t.Fatalf("attempt %d says %d left", i, body.AttemptsLeft)
		}
	}
	if rec := post(mux, "/wallet/email/verify/complete", "alice", `{"email":"alice@example.com","code":"`+wrong+`"}`); rec.Code != http.StatusGone {
		t.Fatalf("last attempt: %d, want 410", rec.Code)
	}
	// Even the right code is now gone with it.
	if rec := post(mux, "/wallet/email/verify/complete", "alice", `{"email":"alice@example.com","code":"`+right+`"}`); rec.Code != http.StatusGone {
		t.Fatalf("right code after burnout: %d, want 410", rec.Code)
	}
}

func TestACodeExpires(t *testing.T) {
	m := &fakeMailer{enabled: true}
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	mux, s := harness(t, m, c)
	post(mux, "/wallet/email/verify/begin", "alice", `{"email":"alice@example.com"}`)
	code := codeFrom(t, m)

	c.t = c.t.Add(codeTTL + time.Second)
	if rec := post(mux, "/wallet/email/verify/complete", "alice", `{"email":"alice@example.com","code":"`+code+`"}`); rec.Code != http.StatusGone {
		t.Fatalf("expired: %d, want 410", rec.Code)
	}
	s.sweep()
	if len(s.pending) != 0 {
		t.Fatalf("sweep left %d holders behind", len(s.pending))
	}
}

func TestASecondCodeHasToWait(t *testing.T) {
	m := &fakeMailer{enabled: true}
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	mux, _ := harness(t, m, c)
	post(mux, "/wallet/email/verify/begin", "alice", `{"email":"alice@example.com"}`)

	rec := post(mux, "/wallet/email/verify/begin", "alice", `{"email":"alice@example.com"}`)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("resend: %d %s", rec.Code, rec.Header().Get("Retry-After"))
	}
	if len(m.sent) != 1 {
		t.Fatalf("%d mails sent, want 1", len(m.sent))
	}

	c.t = c.t.Add(resendAfter + time.Second)
	if rec := post(mux, "/wallet/email/verify/begin", "alice", `{"email":"alice@example.com"}`); rec.Code != 200 {
		t.Fatalf("resend after the wait: %d %s", rec.Code, rec.Body)
	}
	if len(m.sent) != 2 {
		t.Fatalf("%d mails sent, want 2", len(m.sent))
	}
}

func TestTooManyAddressesAtOnce(t *testing.T) {
	m := &fakeMailer{enabled: true}
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	mux, _ := harness(t, m, c)
	for i := 0; i < maxPending; i++ {
		rec := post(mux, "/wallet/email/verify/begin", "alice", `{"email":"a`+string(rune('a'+i))+`@example.com"}`)
		if rec.Code != 200 {
			t.Fatalf("address %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := post(mux, "/wallet/email/verify/begin", "alice", `{"email":"one-too-many@example.com"}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over the cap: %d, want 429", rec.Code)
	}
}

func TestRefusedAddressesAndUnconfiguredMail(t *testing.T) {
	m := &fakeMailer{enabled: true}
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	mux, _ := harness(t, m, c)
	for _, bad := range []string{
		`{"email":"not-an-address"}`,
		`{"email":"a@b.c, evil@attacker.test"}`,
		`{"email":"Someone <a@b.c>"}`,
		`{"email":"a@b.c\nBcc: evil@attacker.test"}`,
		`{"email":""}`,
	} {
		if rec := post(mux, "/wallet/email/verify/begin", "alice", bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d, want 400", bad, rec.Code)
		}
	}
	if len(m.sent) != 0 {
		t.Fatalf("a refused address was mailed: %+v", m.sent)
	}
	if rec := post(mux, "/wallet/email/verify/begin", "", `{"email":"a@b.c"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d, want 401", rec.Code)
	}

	off := &fakeMailer{enabled: false}
	offMux, _ := harness(t, off, c)
	if rec := post(offMux, "/wallet/email/verify/begin", "alice", `{"email":"a@b.c"}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("mail off: %d, want 503", rec.Code)
	}
}

func TestAFailedSendLeavesNothingBehind(t *testing.T) {
	m := &fakeMailer{enabled: true, err: os.ErrDeadlineExceeded}
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	mux, s := harness(t, m, c)
	if rec := post(mux, "/wallet/email/verify/begin", "alice", `{"email":"alice@example.com"}`); rec.Code != http.StatusBadGateway {
		t.Fatalf("send failure: %d, want 502", rec.Code)
	}
	if len(s.pending) != 0 {
		t.Fatal("a code outlived the send that failed")
	}
}
