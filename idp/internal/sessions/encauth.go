// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessions

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/Privasys/idp/internal/tokens"
	"github.com/fxamacker/cbor/v2"
)

// EncAuth is the wallet-signed silent-rebind voucher described in
// `.operations/identity-platform/session-relay/crypto-contract.md` §8.
//
// Field tags use integer CBOR keys to keep the wire size minimal. The
// canonical encoding rules (definite length, sorted integer keys,
// shortest-form integers) are enforced by the cbor.CTAP2EncOptions
// preset that EncAuthEncode() uses.
type EncAuth struct {
	V         uint64 `cbor:"1,keyasint"`
	Sub       string `cbor:"2,keyasint"`
	SID       string `cbor:"3,keyasint"`
	AppID     []byte `cbor:"4,keyasint"`  // SHA-256 of canonical workload OIDs
	EncMeas   []byte `cbor:"5,keyasint"`  // SHA-256 of canonical platform OIDs
	EncPub    []byte `cbor:"6,keyasint"`  // P-256 SEC1 uncompressed (65 B)
	QuoteHash []byte `cbor:"7,keyasint"`  // SHA-256 of leaf RA-TLS cert
	NotBefore uint64 `cbor:"8,keyasint"`  // unix seconds
	NotAfter  uint64 `cbor:"9,keyasint"`  // unix seconds
	HwPub     []byte `cbor:"10,keyasint"` // P-256 SEC1 uncompressed (65 B)
}

// Envelope is the JSON transport for a stored voucher.
type Envelope struct {
	V       uint8  `json:"v"`
	Payload string `json:"payload"`           // base64url(canonical CBOR)
	HwSig   string `json:"hw_sig"`            // base64url(R||S, 64 B)
	IdpSig  string `json:"idp_sig,omitempty"` // base64url(R||S, 64 B); set after IdP co-signs
}

// EncAuthCanonicalCBOR returns the canonical CBOR encoding of payload.
// Used for both signing (input) and verification.
func EncAuthCanonicalCBOR(p *EncAuth) ([]byte, error) {
	opts := cbor.CTAP2EncOptions()
	em, err := opts.EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(p)
}

// DecodeEncAuthPayload parses canonical CBOR back into EncAuth.
func DecodeEncAuthPayload(b []byte) (*EncAuth, error) {
	var p EncAuth
	if err := cbor.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	return &p, nil
}

// VerifyES256Raw verifies a 64-byte R||S signature over msg using a
// P-256 public key in SEC1 uncompressed form (65 B starting with
// 0x04). Returns nil on success.
func VerifyES256Raw(pubSEC1, sig, msg []byte) error {
	if len(pubSEC1) != 65 || pubSEC1[0] != 0x04 {
		return errors.New("invalid SEC1 P-256 public key")
	}
	if len(sig) != 64 {
		return errors.New("signature must be 64 bytes (R||S)")
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(pubSEC1[1:33])
	y := new(big.Int).SetBytes(pubSEC1[33:65])
	if !curve.IsOnCurve(x, y) {
		return errors.New("public key not on curve")
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256(msg)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("signature verification failed")
	}
	return nil
}

// GetEncAuth returns the stored envelope for sid, or ErrNotFound.
// PutEncAuth verifies hw_sig, co-signs with the IdP key, and stores
// the resulting envelope on the session row.
//
// Caller must already have authenticated `userID` (e.g. via the
// wallet session token). PutEncAuth additionally checks that the
// payload's `Sub` matches `userID` and that `SID` matches an active
// session row owned by `userID`.
func (s *Store) PutEncAuth(userID string, payloadBytes, hwSig []byte, issuer *tokens.Issuer) (*Envelope, error) {
	p, err := DecodeEncAuthPayload(payloadBytes)
	if err != nil {
		return nil, err
	}
	if p.V != 1 {
		return nil, fmt.Errorf("unsupported encauth version %d", p.V)
	}
	if p.Sub != userID {
		return nil, errors.New("encauth sub does not match authenticated user")
	}
	if len(p.HwPub) != 65 || p.HwPub[0] != 0x04 {
		return nil, errors.New("hw_pub must be P-256 SEC1 uncompressed")
	}
	if len(p.EncPub) != 65 || p.EncPub[0] != 0x04 {
		return nil, errors.New("enc_pub must be P-256 SEC1 uncompressed")
	}
	if len(p.AppID) != 32 || len(p.EncMeas) != 32 || len(p.QuoteHash) != 32 {
		return nil, errors.New("hash fields must be 32 bytes")
	}
	now := uint64(time.Now().Unix())
	if p.NotAfter <= now {
		return nil, errors.New("encauth already expired")
	}
	if p.NotAfter-p.NotBefore > 100*24*3600 {
		return nil, errors.New("encauth window exceeds 100 days")
	}

	// Bind the voucher to a real session row owned by this user.
	sess, err := s.Get(p.SID)
	if err != nil {
		return nil, fmt.Errorf("sid lookup: %w", err)
	}
	if sess.UserID != userID {
		return nil, errors.New("sid does not belong to authenticated user")
	}
	if sess.RevokedAt != nil {
		return nil, ErrRevoked
	}

	// Verify the wallet signature over the canonical CBOR payload.
	if err := VerifyES256Raw(p.HwPub, hwSig, payloadBytes); err != nil {
		return nil, fmt.Errorf("hw_sig: %w", err)
	}

	// Co-sign with the IdP key over (payload || hw_sig).
	idpInput := make([]byte, 0, len(payloadBytes)+len(hwSig))
	idpInput = append(idpInput, payloadBytes...)
	idpInput = append(idpInput, hwSig...)
	idpSig, err := issuer.SignRaw(idpInput)
	if err != nil {
		return nil, fmt.Errorf("idp_sig: %w", err)
	}

	env := &Envelope{
		V:       1,
		Payload: base64.RawURLEncoding.EncodeToString(payloadBytes),
		HwSig:   base64.RawURLEncoding.EncodeToString(hwSig),
		IdpSig:  base64.RawURLEncoding.EncodeToString(idpSig),
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(
		`UPDATE sessions SET encauth_blob = ? WHERE sid = ? AND revoked_at IS NULL`,
		envBytes, p.SID,
	); err != nil {
		return nil, fmt.Errorf("store encauth: %w", err)
	}
	return env, nil
}

// GetEncAuth returns the stored envelope for sid, or ErrNotFound.
// Caller is expected to have already verified that the requester is
// allowed to read it (typically: the user owns the session, or it is
// being fetched anonymously by the SDK because the JWT claim already
// carries the binding context).
func (s *Store) GetEncAuth(sid string) (*Envelope, error) {
	var blob []byte
	if err := s.db.QueryRow(
		`SELECT COALESCE(encauth_blob, '') FROM sessions WHERE sid = ? AND revoked_at IS NULL`, sid,
	).Scan(&blob); err != nil {
		return nil, ErrNotFound
	}
	if len(blob) == 0 {
		return nil, ErrNotFound
	}
	var env Envelope
	if err := json.Unmarshal(blob, &env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	return &env, nil
}

// HandlePutEncAuth accepts a wallet-signed payload + hw_sig pair and
// stores the co-signed envelope.
//
//	PUT /sessions/{sid}/encauth
//	Authorization: Bearer wallet:<token> | Bearer <jwt>
//	Body: {"payload":"<base64url>", "hw_sig":"<base64url>"}
func (s *Store) HandlePutEncAuth(issuer *tokens.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, _, err := s.authBearer(r, issuer)
		if err != nil {
			httpUnauth(w, err.Error())
			return
		}
		sid := r.PathValue("sid")
		if sid == "" {
			httpErr(w, http.StatusBadRequest, "sid required")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024))
		if err != nil {
			httpErr(w, http.StatusBadRequest, "read body: "+err.Error())
			return
		}
		var req struct {
			Payload string `json:"payload"`
			HwSig   string `json:"hw_sig"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			httpErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		payload, err := base64.RawURLEncoding.DecodeString(req.Payload)
		if err != nil {
			httpErr(w, http.StatusBadRequest, "invalid payload b64")
			return
		}
		hwSig, err := base64.RawURLEncoding.DecodeString(req.HwSig)
		if err != nil {
			httpErr(w, http.StatusBadRequest, "invalid hw_sig b64")
			return
		}
		// Path sid must match payload sid. We re-decode minimally just
		// for the comparison; full validation runs inside PutEncAuth.
		p, err := DecodeEncAuthPayload(payload)
		if err != nil {
			httpErr(w, http.StatusBadRequest, "invalid payload cbor: "+err.Error())
			return
		}
		if p.SID != sid {
			httpErr(w, http.StatusBadRequest, "payload sid mismatch")
			return
		}
		env, err := s.PutEncAuth(userID, payload, hwSig, issuer)
		if err != nil {
			if errors.Is(err, ErrRevoked) {
				httpErr(w, http.StatusGone, err.Error())
				return
			}
			httpErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, env)
	}
}

// HandleGetEncAuth returns the stored envelope for sid. Wallet-session
// or OIDC bearer auth is required; the caller's user must own the sid.
//
//	GET /sessions/{sid}/encauth
//	Authorization: Bearer wallet:<token> | Bearer <jwt>
func (s *Store) HandleGetEncAuth(issuer *tokens.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, _, err := s.authBearer(r, issuer)
		if err != nil {
			httpUnauth(w, err.Error())
			return
		}
		sid := r.PathValue("sid")
		if sid == "" {
			httpErr(w, http.StatusBadRequest, "sid required")
			return
		}
		sess, err := s.Get(sid)
		if err != nil || sess.UserID != userID {
			httpErr(w, http.StatusNotFound, "encauth not found")
			return
		}
		if sess.RevokedAt != nil {
			httpErr(w, http.StatusGone, "session revoked")
			return
		}
		env, err := s.GetEncAuth(sid)
		if err != nil {
			httpErr(w, http.StatusNotFound, "encauth not found")
			return
		}
		writeJSON(w, http.StatusOK, env)
	}
}
