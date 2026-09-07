// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package push

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func serverReturning(t *testing.T, status int, body string) (*Sender, *[]string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	var retired []string
	s := &Sender{
		Client:    srv.Client(),
		DeadToken: func(tok string) { retired = append(retired, tok) },
	}
	// Point the package at the test server by overriding the transport rather
	// than the const, so the production URLs stay unexported and unmodifiable.
	s.Client = &http.Client{Transport: rewriteTo(srv.URL)}
	return s, &retired
}

type rewriter struct{ base string }

func (rw rewriter) RoundTrip(r *http.Request) (*http.Response, error) {
	u := *r.URL
	target, _ := http.NewRequest(r.Method, rw.base+u.Path, r.Body)
	target.Header = r.Header
	return http.DefaultTransport.RoundTrip(target)
}

func rewriteTo(base string) http.RoundTripper { return rewriter{base: base} }

// The failure this package exists to stop: Expo returns HTTP 200 while the
// individual message failed. Every previous sender read that as success.
func TestTicketErrorUnderHTTP200IsAnError(t *testing.T) {
	s, retired := serverReturning(t, 200,
		`{"data":[{"status":"error","message":"is not a registered push notification recipient","details":{"error":"DeviceNotRegistered"}}]}`)

	id, err := s.Send(context.Background(), Message{Token: "ExponentPushToken[dead]"})
	if err == nil {
		t.Fatal("a failed ticket under HTTP 200 was reported as success")
	}
	if id != "" {
		t.Errorf("ticket id %q returned for a failed send", id)
	}
	if !IsDeadToken(err) {
		t.Errorf("err = %v, want a dead-token error", err)
	}
	if len(*retired) != 1 || (*retired)[0] != "ExponentPushToken[dead]" {
		t.Errorf("retired = %v, want the dead token", *retired)
	}
}

func TestSuccessfulSendReturnsTheTicketID(t *testing.T) {
	s, retired := serverReturning(t, 200, `{"data":[{"status":"ok","id":"tkt-1"}]}`)

	id, err := s.Send(context.Background(), Message{Token: "ExponentPushToken[live]"})
	if err != nil {
		t.Fatal(err)
	}
	if id != "tkt-1" {
		t.Errorf("ticket id = %q", id)
	}
	// A live token must never be retired.
	if len(*retired) != 0 {
		t.Errorf("retired %v on a successful send", *retired)
	}
}

func TestNonSuccessStatusIsAnError(t *testing.T) {
	s, _ := serverReturning(t, 400, `{"errors":[{"code":"PUSH_TOO_MANY_EXPERIENCE_IDS"}]}`)
	if _, err := s.Send(context.Background(), Message{Token: "t"}); err == nil {
		t.Fatal("HTTP 400 was reported as success")
	}
}

// A 200 whose body we cannot parse is still a send we cannot vouch for.
func TestUnreadableTicketIsAnError(t *testing.T) {
	s, _ := serverReturning(t, 200, `not json`)
	if _, err := s.Send(context.Background(), Message{Token: "t"}); err == nil {
		t.Fatal("an unparseable response was reported as success")
	}
}

func TestEmptyTicketListIsAnError(t *testing.T) {
	s, _ := serverReturning(t, 200, `{"data":[]}`)
	if _, err := s.Send(context.Background(), Message{Token: "t"}); err == nil {
		t.Fatal("an empty ticket list was reported as success")
	}
}

// An absent receipt means "not yet", never "not attempted". Reading it the
// other way sent the 2026-09-07 investigation down the wrong path.
func TestAbsentReceiptIsPendingNotFailure(t *testing.T) {
	s, retired := serverReturning(t, 200, `{"data":{}}`)

	got, err := s.Receipts(context.Background(), []string{"tkt-1"}, map[string]string{"tkt-1": "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Pending {
		t.Fatalf("got %+v, want one pending result", got)
	}
	if got[0].Err != nil {
		t.Errorf("a pending receipt reported an error: %v", got[0].Err)
	}
	if len(*retired) != 0 {
		t.Errorf("a pending receipt retired a token: %v", *retired)
	}
}

func TestDeliveredReceipt(t *testing.T) {
	s, _ := serverReturning(t, 200, `{"data":{"tkt-1":{"status":"ok"}}}`)
	got, err := s.Receipts(context.Background(), []string{"tkt-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Delivered {
		t.Fatalf("got %+v, want delivered", got)
	}
}

// The whole reason receipts are read at all: this is where a dead device
// usually surfaces, not at ticket time.
func TestReceiptDeviceNotRegisteredRetiresTheToken(t *testing.T) {
	s, retired := serverReturning(t, 200,
		`{"data":{"tkt-1":{"status":"error","message":"gone","details":{"error":"DeviceNotRegistered"}}}}`)

	got, err := s.Receipts(context.Background(), []string{"tkt-1"}, map[string]string{"tkt-1": "ExponentPushToken[dead]"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Err == nil || got[0].Delivered {
		t.Fatalf("got %+v, want a failed result", got)
	}
	if len(*retired) != 1 || (*retired)[0] != "ExponentPushToken[dead]" {
		t.Fatalf("retired = %v, want the dead token", *retired)
	}
}

// A transient delivery error must NOT retire the token: the device is fine and
// will accept the next push.
func TestTransientReceiptErrorKeepsTheToken(t *testing.T) {
	s, retired := serverReturning(t, 200,
		`{"data":{"tkt-1":{"status":"error","message":"try later","details":{"error":"MessageRateExceeded"}}}}`)

	got, _ := s.Receipts(context.Background(), []string{"tkt-1"}, map[string]string{"tkt-1": "tok"})
	if len(got) != 1 || got[0].Err == nil {
		t.Fatalf("got %+v, want a failed result", got)
	}
	if len(*retired) != 0 {
		t.Fatalf("a transient error retired the token: %v", *retired)
	}
}

// --- The sweep -----------------------------------------------------------

type fakeStore struct {
	due       []PushTicket
	recorded  map[string]string
	deletedT  []string
	deadToken []string
}

func (f *fakeStore) RecordPushTicket(ticketID, userID, pushToken string) error {
	if f.recorded == nil {
		f.recorded = map[string]string{}
	}
	f.recorded[ticketID] = pushToken
	return nil
}
func (f *fakeStore) DeletePushToken(t string) error                          { f.deadToken = append(f.deadToken, t); return nil }
func (f *fakeStore) DuePushTickets(time.Duration, int) ([]PushTicket, error) { return f.due, nil }
func (f *fakeStore) DeletePushTickets(ids []string) error {
	f.deletedT = append(f.deletedT, ids...)
	return nil
}

func TestSweepClearsAnsweredTicketsAndKeepsPendingOnes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// tkt-1 delivered, tkt-2 dead device, tkt-3 no receipt yet.
		_, _ = w.Write([]byte(`{"data":{
			"tkt-1":{"status":"ok"},
			"tkt-2":{"status":"error","message":"gone","details":{"error":"DeviceNotRegistered"}}
		}}`))
	}))
	defer srv.Close()

	db := &fakeStore{due: []PushTicket{
		{TicketID: "tkt-1", UserID: "u1", PushToken: "tok-1"},
		{TicketID: "tkt-2", UserID: "u2", PushToken: "tok-2"},
		{TicketID: "tkt-3", UserID: "u3", PushToken: "tok-3"},
	}}

	s := For(db)
	s.Client = &http.Client{Transport: rewriteTo(srv.URL)}
	results, err := s.Receipts(context.Background(), []string{"tkt-1", "tkt-2", "tkt-3"},
		map[string]string{"tkt-1": "tok-1", "tkt-2": "tok-2", "tkt-3": "tok-3"})
	if err != nil {
		t.Fatal(err)
	}

	var pending int
	for _, r := range results {
		if r.Pending {
			pending++
		}
	}
	if pending != 1 {
		t.Errorf("pending = %d, want exactly tkt-3 left for the next sweep", pending)
	}
	if len(db.deadToken) != 1 || db.deadToken[0] != "tok-2" {
		t.Errorf("retired = %v, want only the dead device's token", db.deadToken)
	}
}

func TestNotifyRecordsTheTicket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"status":"ok","id":"tkt-9"}]}`))
	}))
	defer srv.Close()

	db := &fakeStore{}
	s := For(db)
	s.Client = &http.Client{Transport: rewriteTo(srv.URL)}
	id, err := s.Send(context.Background(), Message{Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RecordPushTicket(id, "u1", "tok"); err != nil {
		t.Fatal(err)
	}
	if db.recorded["tkt-9"] != "tok" {
		t.Fatalf("recorded = %v, want the ticket against its token", db.recorded)
	}
}
