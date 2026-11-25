// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package push

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Sends and receipt lookups present the Expo access token once one is
// configured, and nothing when none is.
func TestSendsAreAuthenticatedWhenConfigured(t *testing.T) {
	var seen []string
	var bodies []string
	s := &Sender{Client: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.Header.Get("Authorization"))
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"data":[{"status":"ok","id":"t1"}]}`))}, nil
	})}}
	defer SetAccessToken("")

	SetAccessToken("")
	if _, err := s.Send(context.Background(), Message{Token: "tok", Title: "a", Body: "b"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	SetAccessToken("secret-expo-token")
	if _, err := s.Send(context.Background(), Message{Token: "tok", Title: "a", Body: "b", Badge: 3}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := s.badge(context.Background(), "tok", 2); err != nil {
		t.Fatalf("badge: %v", err)
	}
	if seen[0] != "" || seen[1] != "Bearer secret-expo-token" || seen[2] != "Bearer secret-expo-token" {
		t.Fatalf("authorization headers = %q", seen)
	}
	// The number rides the request's own push, and the correction is the
	// number and nothing else.
	if !strings.Contains(bodies[1], `"badge":3`) || strings.Contains(bodies[0], `"badge"`) {
		t.Fatalf("badge on the request push: %s | %s", bodies[0], bodies[1])
	}
	if bodies[2] != `[{"badge":2,"priority":"normal","to":"tok"}]` {
		t.Fatalf("the correction carries more than the number: %s", bodies[2])
	}
}
