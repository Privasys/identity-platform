// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package support

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeMailer struct {
	enabled bool
	sent    []struct{ to, subject, body string }
	err     error
}

func (m *fakeMailer) Enabled() bool { return m.enabled }

func (m *fakeMailer) Send(to, subject, body string) error {
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, struct{ to, subject, body string }{to, subject, body})
	return nil
}

func post(t *testing.T, h *Handler, body any, ip string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/wallet/report", strings.NewReader(string(raw)))
	if ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	w := httptest.NewRecorder()
	h.HandleReport(w, req)
	return w
}

func TestForwardsToTheConfiguredInbox(t *testing.T) {
	m := &fakeMailer{enabled: true}
	h := NewHandler(m, "support@privasys.org")

	w := post(t, h, reportRequest{
		Message:  "RA-TLS inspect failed: UnknownIssuer",
		Platform: "ios",
		Version:  "1.4.1",
		Contact:  "someone@example.com",
	}, "203.0.113.7")

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", w.Code, w.Body.String())
	}
	if len(m.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(m.sent))
	}
	got := m.sent[0]
	if got.to != "support@privasys.org" {
		t.Errorf("to = %q", got.to)
	}
	if got.subject != "Wallet error report (ios 1.4.1)" {
		t.Errorf("subject = %q", got.subject)
	}
	for _, want := range []string{"UnknownIssuer", "someone@example.com", "203.0.113.7"} {
		if !strings.Contains(got.body, want) {
			t.Errorf("body missing %q:\n%s", want, got.body)
		}
	}
}

// The recipient is a constant. Whatever a caller puts in the request, the mail
// goes to the support inbox, so the endpoint cannot be used as a relay.
func TestRecipientIsNeverTakenFromTheRequest(t *testing.T) {
	m := &fakeMailer{enabled: true}
	h := NewHandler(m, "support@privasys.org")

	w := post(t, h, map[string]string{
		"message": "hello",
		"to":      "victim@example.com",
		"contact": "victim@example.com",
	}, "203.0.113.8")

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d", w.Code)
	}
	if m.sent[0].to != "support@privasys.org" {
		t.Fatalf("to = %q, want the configured inbox", m.sent[0].to)
	}
}

// A newline in a value that reaches the subject line is how a caller writes
// headers we did not intend.
func TestSubjectCarriesNoLineBreaks(t *testing.T) {
	m := &fakeMailer{enabled: true}
	h := NewHandler(m, "support@privasys.org")

	post(t, h, reportRequest{
		Message:  "hello",
		Platform: "ios\r\nBcc: victim@example.com",
		Version:  "1.4.1\nX-Injected: yes",
	}, "203.0.113.9")

	subject := m.sent[0].subject
	if strings.ContainsAny(subject, "\r\n") {
		t.Fatalf("subject contains a line break: %q", subject)
	}
	if !strings.Contains(subject, "ios") {
		t.Errorf("subject lost the platform: %q", subject)
	}
}

func TestRejectsAnEmptyReport(t *testing.T) {
	m := &fakeMailer{enabled: true}
	h := NewHandler(m, "support@privasys.org")

	if w := post(t, h, reportRequest{Message: "   "}, "203.0.113.10"); w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if len(m.sent) != 0 {
		t.Fatal("an empty report was forwarded")
	}
}

func TestRateLimitsPerAddress(t *testing.T) {
	m := &fakeMailer{enabled: true}
	h := NewHandler(m, "support@privasys.org")

	for i := 0; i < perIPHourly; i++ {
		if w := post(t, h, reportRequest{Message: "again"}, "203.0.113.11"); w.Code != http.StatusAccepted {
			t.Fatalf("report %d rejected with %d", i, w.Code)
		}
	}
	if w := post(t, h, reportRequest{Message: "again"}, "203.0.113.11"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	// A different address still gets through: the limit is per source, not a
	// global gate that one noisy client can close for everyone.
	if w := post(t, h, reportRequest{Message: "first"}, "203.0.113.12"); w.Code != http.StatusAccepted {
		t.Fatalf("second address rejected with %d", w.Code)
	}
}

func TestUnconfiguredMailerSaysSoRatherThanFailingQuietly(t *testing.T) {
	h := NewHandler(&fakeMailer{enabled: false}, "support@privasys.org")
	if w := post(t, h, reportRequest{Message: "hello"}, "203.0.113.13"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}

	h = NewHandler(&fakeMailer{enabled: true}, "")
	if w := post(t, h, reportRequest{Message: "hello"}, "203.0.113.14"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d with no inbox configured, want 503", w.Code)
	}
}

func TestOversizedReportIsTruncatedNotDropped(t *testing.T) {
	m := &fakeMailer{enabled: true}
	h := NewHandler(m, "support@privasys.org")

	post(t, h, reportRequest{Message: strings.Repeat("a", maxMessageRunes+500)}, "203.0.113.15")

	if len(m.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(m.sent))
	}
	if !strings.Contains(m.sent[0].body, "[truncated]") {
		t.Error("an oversized report was not marked as truncated")
	}
}
