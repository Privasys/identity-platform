package federation

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
)

func adminOK(w http.ResponseWriter, r *http.Request, adminToken string) bool {
	// A route that takes customer credentials stays shut without a token.
	if adminToken == "" || strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != adminToken {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, ErrNoKeyService):
		status = http.StatusServiceUnavailable
	case err.Error() == "client not found":
		status = http.StatusNotFound
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// HandleSet handles POST /clients/{id}/federation/{provider}. An empty body
// deletes the entry. For a certificate credential the reply carries the public
// certificate to upload at the upstream provider; a secret is taken once and
// never returned.
func (s *Service) HandleSet(adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminOK(w, r, adminToken) {
			return
		}
		clientID, provider := r.PathValue("id"), r.PathValue("provider")
		var req SetRequest
		err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req)
		if errors.Is(err, io.EOF) {
			if err := s.Delete(r.Context(), clientID, provider); err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, map[string]any{"client_id": clientID, "provider": provider, "deleted": true})
			return
		}
		if err != nil {
			writeError(w, errors.New("invalid JSON body"))
			return
		}
		view, err := s.Set(r.Context(), clientID, provider, req)
		if err != nil {
			log.Printf("federation: set %s/%s: %v", clientID, provider, err)
			writeError(w, err)
			return
		}
		writeJSON(w, view)
	}
}

// HandleConfirm handles POST /clients/{id}/federation/{provider}/confirm: the
// customer has uploaded a rotated certificate.
func (s *Service) HandleConfirm(adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminOK(w, r, adminToken) {
			return
		}
		view, err := s.Confirm(r.Context(), r.PathValue("id"), r.PathValue("provider"))
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, view)
	}
}

// HandleList handles GET /clients/{id}/federation.
func (s *Service) HandleList(adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminOK(w, r, adminToken) {
			return
		}
		views, err := s.List(r.PathValue("id"))
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, map[string]any{"federation": views})
	}
}

// HandleExpiries handles GET /admin/federation/expiries, for the weekly
// operations check beside the vault key ages.
func (s *Service) HandleExpiries(adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminOK(w, r, adminToken) {
			return
		}
		out, err := s.Expiries()
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, map[string]any{"certificates": out})
	}
}
