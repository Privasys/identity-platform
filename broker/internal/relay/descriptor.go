// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// descriptorTTL bounds how long a published descriptor is retrievable.
	// Wallets typically GET within seconds of the SDK PUT, so 5 min is
	// conservative — it covers the user walking up to their phone or
	// re-scanning after a transient camera glitch.
	descriptorTTL = 5 * time.Minute

	// descriptorMaxSize caps individual descriptors. The current shape is
	// ~800 bytes; 8 KB leaves room for policy fields and OID lists.
	descriptorMaxSize = 8 * 1024
)

var (
	descriptorsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "broker_descriptors_active",
		Help: "Number of published, unexpired connect descriptors.",
	})
	descriptorRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "broker_descriptor_requests_total",
		Help: "Connect descriptor requests by method and outcome.",
	}, []string{"method", "outcome"})
)

type descriptor struct {
	body      []byte
	expiresAt time.Time
}

// DescriptorStore is an in-memory, TTL'd map keyed by sessionId.
//
// The relay is the only entity (besides the SDK that wrote) that ever sees
// the descriptor bytes; the QR pins SHA-256(descriptor)[:16] so the wallet
// can detect substitution. Single-write per sessionId prevents an
// attacker who learns a sessionId from racing the legit SDK.
type DescriptorStore struct {
	mu sync.Mutex
	m  map[string]descriptor
}

func NewDescriptorStore() *DescriptorStore {
	s := &DescriptorStore{m: make(map[string]descriptor)}
	go s.gcLoop()
	return s
}

func (s *DescriptorStore) gcLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		s.gc()
	}
}

func (s *DescriptorStore) gc() {
	now := time.Now()
	s.mu.Lock()
	for k, v := range s.m {
		if now.After(v.expiresAt) {
			delete(s.m, k)
		}
	}
	descriptorsActive.Set(float64(len(s.m)))
	s.mu.Unlock()
}

// HandleConnect serves PUT and GET on /connect/{sessionId}.
//
//   PUT  — SDK publishes the descriptor (one-shot per sessionId). Body is
//          JSON, capped at descriptorMaxSize. Returns 204 on success,
//          409 if the sessionId already has a descriptor, 400 on invalid
//          JSON or oversize body.
//
//   GET  — wallet fetches the descriptor and verifies the QR hash pin
//          against the body. Multi-read within TTL so a wallet can retry
//          after a transient network failure.
func (s *DescriptorStore) HandleConnect(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedOrigin(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "PUT, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "600")
	}

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	sid := strings.TrimPrefix(r.URL.Path, "/connect/")
	if sid == "" || strings.ContainsAny(sid, "/?#") || !sessionIDPattern.MatchString(sid) {
		descriptorRequests.WithLabelValues(r.Method, "bad_id").Inc()
		http.Error(w, `{"error":"invalid session id"}`, http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, descriptorMaxSize+1))
		if err != nil {
			descriptorRequests.WithLabelValues("PUT", "read_err").Inc()
			http.Error(w, `{"error":"bad request body"}`, http.StatusBadRequest)
			return
		}
		if len(body) > descriptorMaxSize {
			descriptorRequests.WithLabelValues("PUT", "too_large").Inc()
			http.Error(w, `{"error":"descriptor too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		var probe map[string]interface{}
		if err := json.Unmarshal(body, &probe); err != nil {
			descriptorRequests.WithLabelValues("PUT", "bad_json").Inc()
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		s.mu.Lock()
		if existing, ok := s.m[sid]; ok && time.Now().Before(existing.expiresAt) {
			s.mu.Unlock()
			descriptorRequests.WithLabelValues("PUT", "conflict").Inc()
			http.Error(w, `{"error":"already published"}`, http.StatusConflict)
			return
		}
		s.m[sid] = descriptor{body: body, expiresAt: time.Now().Add(descriptorTTL)}
		descriptorsActive.Set(float64(len(s.m)))
		s.mu.Unlock()

		descriptorRequests.WithLabelValues("PUT", "ok").Inc()
		w.WriteHeader(http.StatusNoContent)

	case http.MethodGet:
		s.mu.Lock()
		d, ok := s.m[sid]
		s.mu.Unlock()
		if !ok || time.Now().After(d.expiresAt) {
			descriptorRequests.WithLabelValues("GET", "miss").Inc()
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		descriptorRequests.WithLabelValues("GET", "ok").Inc()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(d.body)

	default:
		descriptorRequests.WithLabelValues(r.Method, "method_not_allowed").Inc()
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}
