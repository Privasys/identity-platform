// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package support receives error reports from the wallet and forwards them to
// the support inbox.
//
// There is no ticketing system yet, so the transport is email: the same
// Microsoft Graph mailer the recovery flow uses, addressed to a fixed inbox the
// operator configures. Nothing here reads a recipient from the request, so the
// endpoint cannot be turned into an open relay whatever a caller sends.
//
// The endpoint is deliberately UNAUTHENTICATED. A holder reporting an error is
// very often a holder who could not sign in, and a report surface that needs
// the thing that just failed is a report surface nobody can use. What that
// costs is spam, so the protections here are rate limiting, hard size caps, and
// the fixed recipient rather than a credential.
package support

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Mailer is the slice of recovery.Mailer this package needs.
type Mailer interface {
	Enabled() bool
	Send(to, subject, body string) error
}

const (
	// The whole request. A report carries the recent log buffer, so it is not
	// small, but it has no business approaching a megabyte.
	maxRequestBytes = 128 * 1024
	maxMessageRunes = 60000
	maxContactRunes = 200
	maxLabelRunes   = 64

	// Per-IP and process-wide budgets, both hourly. The global one exists
	// because a botnet defeats the per-IP one, and the failure that would
	// cause (a flooded support inbox) is worse than a few dropped reports.
	perIPHourly  = 5
	globalHourly = 300

	rateWindow = time.Hour
)

// Handler serves POST /wallet/report.
type Handler struct {
	mailer Mailer
	to     string

	mu     sync.Mutex
	perIP  map[string][]time.Time
	global []time.Time
}

// NewHandler returns a handler that mails reports to `to`. An empty `to`, or a
// mailer with no credentials, leaves the endpoint responding 503 so the wallet
// falls back to telling the holder to copy the report by hand.
func NewHandler(mailer Mailer, to string) *Handler {
	return &Handler{mailer: mailer, to: to, perIP: make(map[string][]time.Time)}
}

type reportRequest struct {
	// The report body the wallet built and showed the holder verbatim.
	Message string `json:"message"`
	// Optional: how the holder would like to be reached. Carried in the BODY
	// only, never as a header, so it cannot inject one.
	Contact  string `json:"contact"`
	Platform string `json:"platform"`
	Version  string `json:"version"`
	// Free-text label for where in the app the report was raised.
	Context string `json:"context"`
}

// HandleReport accepts a report and forwards it to the support inbox.
func (h *Handler) HandleReport(w http.ResponseWriter, r *http.Request) {
	if !h.enabled() {
		writeErr(w, http.StatusServiceUnavailable, "reporting_unavailable",
			"Error reporting is not configured on this server.")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var req reportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "Could not read the report.")
		return
	}

	message := strings.TrimSpace(req.Message)
	if message == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "The report is empty.")
		return
	}
	message = truncateRunes(message, maxMessageRunes)

	ip := clientIP(r)
	if !h.allow(ip) {
		// 429 without a Retry-After: the answer the wallet offers is the copy
		// button, not a retry on a timer.
		writeErr(w, http.StatusTooManyRequests, "rate_limited",
			"Too many reports have been sent recently. Please copy the report and send it by hand.")
		return
	}

	subject := buildSubject(req)
	body := buildBody(req, message, ip)

	if err := h.mailer.Send(h.to, subject, body); err != nil {
		log.Printf("[support] send report: %v", err)
		writeErr(w, http.StatusBadGateway, "send_failed", "The report could not be sent.")
		return
	}
	log.Printf("[support] report forwarded (%d bytes, platform=%q)", len(message), oneLine(req.Platform, maxLabelRunes))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "sent", "destination": h.to})
}

func (h *Handler) enabled() bool {
	return h.to != "" && h.mailer != nil && h.mailer.Enabled()
}

// allow records an attempt and reports whether it fits within both budgets.
func (h *Handler) allow(ip string) bool {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()

	h.global = within(h.global, now)
	if len(h.global) >= globalHourly {
		return false
	}
	hits := within(h.perIP[ip], now)
	if len(hits) >= perIPHourly {
		h.perIP[ip] = hits
		return false
	}

	h.perIP[ip] = append(hits, now)
	h.global = append(h.global, now)

	// Drop IPs whose window has emptied, so a long-running process does not
	// accumulate an entry for every client that ever reported.
	if len(h.perIP) > 4096 {
		for k, v := range h.perIP {
			if len(within(v, now)) == 0 {
				delete(h.perIP, k)
			}
		}
	}
	return true
}

func within(times []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-rateWindow)
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	return kept
}

// buildSubject keeps the platform and version the caller sent but never their
// line breaks: a subject is a header, and a header with a newline in it is a
// way to write headers we did not intend.
func buildSubject(req reportRequest) string {
	platform := oneLine(req.Platform, maxLabelRunes)
	version := oneLine(req.Version, maxLabelRunes)
	switch {
	case platform != "" && version != "":
		return fmt.Sprintf("Wallet error report (%s %s)", platform, version)
	case platform != "":
		return fmt.Sprintf("Wallet error report (%s)", platform)
	default:
		return "Wallet error report"
	}
}

func buildBody(req reportRequest, message, ip string) string {
	var b strings.Builder
	b.WriteString("An error report was submitted from the Privasys Wallet.\n\n")
	writeField(&b, "Platform", oneLine(req.Platform, maxLabelRunes))
	writeField(&b, "Version", oneLine(req.Version, maxLabelRunes))
	writeField(&b, "Where", oneLine(req.Context, maxLabelRunes))
	writeField(&b, "Contact", oneLine(req.Contact, maxContactRunes))
	writeField(&b, "Received", time.Now().UTC().Format(time.RFC3339))
	writeField(&b, "Source", ip)
	b.WriteString("\nThe holder saw this report in full before sending it.\n")
	b.WriteString("\n----- report -----\n")
	b.WriteString(message)
	b.WriteString("\n----- end -----\n")
	return b.String()
}

func writeField(b *strings.Builder, label, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(b, "%-9s %s\n", label+":", value)
}

// oneLine collapses every kind of line break and control character, so a value
// bound for a header or for a labelled line cannot forge either.
func oneLine(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return truncateRunes(strings.TrimSpace(strings.Join(strings.Fields(s), " ")), max)
}

func truncateRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "\n[truncated]"
}

// clientIP trusts the last hop of X-Forwarded-For, which is the one our own
// reverse proxy wrote; earlier entries are whatever the caller claimed. Used
// only for rate limiting and for one line in the report.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func writeErr(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}
