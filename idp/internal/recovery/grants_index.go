// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"encoding/json"
	"io"
	"net/http"
)

// Grants index endpoints.
//
// A holder's standing capabilities live at the services that enforce them:
// Drive, the mail connector, each app's own enclave OS for holder folders.
// Each of those answers "what does this holder hold here" for an
// authenticated holder, so a wallet can rebuild its list of grants, and the
// revoke button on each, from the services themselves. What it cannot rebuild
// on a new phone is WHICH services to ask. This blob is that list.
//
// It sits beside the sovereign backup rather than inside it because it
// changes at every approval, and the backup can only be re-wrapped while the
// wallet holds the recovery phrase, which it never does during an approval.
// The wallet encrypts this one under a key derived from the sovereign data
// root instead: the root is on the phone at approval time, and recovery
// restores the root from the phrase-wrapped backup, so the chain is phrase,
// root, index key, index.
//
// Opaque ciphertext to the IdP. What the IdP does learn is its size and when
// it changes, which says that an approval or a revoke happened, not what or
// with whom.

// maxGrantsIndexBytes bounds the stored blob. An entry is an app id and at
// most a URL, so 16 KiB holds a hundred or so services, far beyond any real
// holder, without letting the endpoint become general-purpose storage.
const maxGrantsIndexBytes = 16 * 1024

// HandlePutGrantsIndex stores (replaces) the caller's grants index.
// PUT /recovery/grants-index  (requires wallet sessionToken or JWT bearer)
func (h *Handler) HandlePutGrantsIndex(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}
	var req struct {
		Blob string `json:"blob"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxGrantsIndexBytes+1024)).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}
	if req.Blob == "" || len(req.Blob) > maxGrantsIndexBytes || !backupBlobShape.MatchString(req.Blob) {
		http.Error(w, `{"error":"blob must be non-empty base64url, at most 16KiB"}`, http.StatusBadRequest)
		return
	}
	if err := h.db.PutGrantsIndex(userID, req.Blob); err != nil {
		http.Error(w, `{"error":"failed to store grants index"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stored"})
}

// HandleGetGrantsIndex returns the caller's grants index, 404 when none is
// stored (a holder who has never approved a capability, or a wallet from
// before this existed).
// GET /recovery/grants-index  (requires wallet sessionToken or JWT bearer)
func (h *Handler) HandleGetGrantsIndex(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}
	blob, err := h.db.GetGrantsIndex(userID)
	if err != nil {
		http.Error(w, `{"error":"failed to load grants index"}`, http.StatusInternalServerError)
		return
	}
	if blob == "" {
		http.Error(w, `{"error":"no grants index stored"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"blob": blob})
}
