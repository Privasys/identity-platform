// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"

	"github.com/Privasys/idp/internal/store"
)

// Sovereign backup blob endpoints (the sovereign-data framework, Phase 2).
//
// The wallet wraps its root secrets (sovereign data root + pairwise seed)
// client-side under material derived from the 24-word recovery phrase and
// stores the result here as one opaque blob per user. The server cannot
// open it: it holds only sha256(phrase), from which the wallet's HKDF
// input cannot be derived. The wallet re-wraps and re-PUTs at every
// ceremony that holds the phrase (first registration, regeneration,
// recovery), and GETs after account recovery — by which point the device
// has re-registered and holds a wallet session, so plain bearer auth
// suffices and the blob is never served pre-authentication.
//
// Several phones of one holder may write it, so each write names the version
// it replaces and an older one is refused (409 with the stored version).

// maxBackupBlobBytes bounds the stored blob. The real payload is well
// under 1 KiB (versioned envelope over two 32-byte secrets); 8 KiB gives
// generous headroom for future payload versions without letting the
// endpoint become general-purpose storage.
const maxBackupBlobBytes = 8 * 1024

// base64url without padding — the only shape the wallet produces.
var backupBlobShape = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// HandlePutBackup stores (replaces) the caller's sovereign backup blob.
// PUT /recovery/backup  {"blob": "...", "version": <stored version, optional>}
// (requires wallet sessionToken or JWT bearer)
func (h *Handler) HandlePutBackup(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}
	var req struct {
		Blob string `json:"blob"`
		// Version is the stored version this write replaces (0: none yet).
		// Wallets before devices omit it and write unconditionally.
		Version *int64 `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBackupBlobBytes+1024)).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}
	if req.Blob == "" || len(req.Blob) > maxBackupBlobBytes || !backupBlobShape.MatchString(req.Blob) {
		http.Error(w, `{"error":"blob must be non-empty base64url, at most 8KiB"}`, http.StatusBadRequest)
		return
	}
	putVersioned(w, h.db, "sovereign_backups", userID, req.Blob, req.Version)
}

// HandleGetBackup returns the caller's sovereign backup blob and its version,
// 404 when none is stored (a pre-framework account).
// GET /recovery/backup  (requires wallet sessionToken or JWT bearer)
func (h *Handler) HandleGetBackup(w http.ResponseWriter, r *http.Request) {
	userID := h.authenticateBearer(w, r)
	if userID == "" {
		return
	}
	blob, version, err := h.db.GetVersioned("sovereign_backups", userID)
	if err != nil {
		http.Error(w, `{"error":"failed to load backup"}`, http.StatusInternalServerError)
		return
	}
	if blob == "" {
		http.Error(w, `{"error":"no backup stored"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"blob": blob, "version": version})
}

// putVersioned stores a blob several phones write, refusing (409, with the
// stored version) a write based on an older one. A nil version writes
// unconditionally.
func putVersioned(w http.ResponseWriter, db *store.DB, table, userID, blob string, version *int64) {
	expect := int64(-1)
	if version != nil {
		expect = *version
	}
	next, err := db.PutVersioned(table, userID, blob, expect)
	switch {
	case errors.Is(err, store.ErrVersionConflict):
		writeJSONStatus(w, http.StatusConflict, map[string]any{"error": "stored version is newer", "version": next})
	case err != nil:
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "failed to store"})
	default:
		writeJSONStatus(w, http.StatusOK, map[string]any{"status": "stored", "version": next})
	}
}
