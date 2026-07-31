// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package wia

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Wallet-asserted session completion (the WIA-grade wallet fee exemption).
//
// The `wallet=true` access-token class drives the free_for:["wallet"] API-fee
// exemption checked inside attested app runtimes, so it must be unforgeable:
// it may appear iff the pending OIDC session was asserted by an ENROLLED,
// ATTESTED wallet instance proving possession of its WIA-bound holder key.
// Nothing client-declared, nothing inferable from WebAuthn alone (a browser
// passkey is not a wallet), no path that mints the class without the wallet
// app.
//
// The wallet calls POST /session/assert-wallet during its approval flow,
// before or after the session completes (both orders are handled): the
// request carries the instance's WIA (wia+jwt, issued at enrolment against a
// hardware-attested holder key) plus an ECDSA proof-of-possession by that
// holder key over {session_id, ts, nonce}. What the assert proves is that an
// enrolled wallet instance participated in approving THIS session; the
// session's actual authentication still happens through the existing FIDO2 /
// relay paths.

// assertFreshness bounds how old (or future-dated) an assert signature may
// be. The effect of an assert is idempotent per session, so a replayed blob
// within the window changes nothing; the bound exists to stop indefinite
// offline reuse of a captured signature.
const assertFreshness = 2 * time.Minute

// AssertOutcome is what the session-store callback reports back.
type AssertOutcome int

const (
	// AssertSessionNotFound: no pending (unexpired) session with that id.
	AssertSessionNotFound AssertOutcome = iota
	// AssertMarked: the pending session is now wallet-asserted; the auth
	// code minted at completion will carry the class.
	AssertMarked
	// AssertPatchedCompletedCode: the session had already completed, and the
	// existing auth code was patched with the class (assert lost the race).
	AssertPatchedCompletedCode
)

// SessionWalletAsserter marks the OIDC session (and, when it already
// completed, its auth code) wallet-asserted. instanceKey is a stable,
// non-identifying thumbprint of the asserting instance's holder key, kept
// for audit logs only.
type SessionWalletAsserter func(sessionID, instanceKey string) AssertOutcome

type assertRequest struct {
	SessionID string `json:"session_id"`
	TS        int64  `json:"ts"`    // unix seconds, bound into the signature
	Nonce     string `json:"nonce"` // client random, bound into the signature
	WIA       string `json:"wia"`   // the instance's wia+jwt
	HolderSig string `json:"holder_sig"`
}

// AssertPayload is the exact byte string the holder key signs (SHA-256 is
// applied by the platform signer). Shared with the wallet client; keep the
// two in lockstep.
func AssertPayload(sessionID string, ts int64, nonce string) []byte {
	return []byte(fmt.Sprintf("privasys:assert-wallet\n%s\n%d\n%s", sessionID, ts, nonce))
}

// HandleAssertSession (POST /session/assert-wallet) verifies the WIA and the
// holder-key proof-of-possession, then marks the pending session
// wallet-asserted via the callback.
func (h *Handler) HandleAssertSession(assert SessionWalletAsserter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "failed to read body")
			return
		}
		var req assertRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.SessionID == "" || req.WIA == "" || req.HolderSig == "" || req.Nonce == "" {
			writeErr(w, http.StatusBadRequest, "session_id, ts, nonce, wia and holder_sig are required")
			return
		}
		if d := time.Since(time.Unix(req.TS, 0)); d > assertFreshness || d < -assertFreshness {
			writeErr(w, http.StatusBadRequest, "assert timestamp outside freshness window")
			return
		}

		holderPub, instanceKey, err := h.verifyWIA(req.WIA)
		if err != nil {
			writeErr(w, http.StatusForbidden, "invalid wallet instance attestation: "+err.Error())
			return
		}

		sig, err := decodeB64Any(req.HolderSig)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "malformed holder_sig")
			return
		}
		if err := verifyHolderPoP(holderPub, AssertPayload(req.SessionID, req.TS, req.Nonce), sig); err != nil {
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}

		switch assert(req.SessionID, instanceKey) {
		case AssertSessionNotFound:
			writeErr(w, http.StatusNotFound, "session not found or expired")
		case AssertPatchedCompletedCode:
			log.Printf("assert-wallet: session %s patched after completion (instance %s)", req.SessionID, instanceKey)
			writeJSON(w, http.StatusOK, map[string]string{"status": "asserted"})
		default:
			log.Printf("assert-wallet: session %s wallet-asserted (instance %s)", req.SessionID, instanceKey)
			writeJSON(w, http.StatusOK, map[string]string{"status": "asserted"})
		}
	}
}

// verifyWIA checks the token is a wia+jwt signed by the wallet-provider key
// and returns the holder public key it binds plus a stable, non-identifying
// instance thumbprint (SHA-256 over the SEC1 point) for audit logs.
func (h *Handler) verifyWIA(tokenStr string) (*ecdsa.PublicKey, string, error) {
	// The JOSE typ header must say wia+jwt: the wallet-provider issuer only
	// signs WIAs today, but the explicit check keeps a future token type
	// signed by the same key from doubling as one.
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, "", errors.New("malformed token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", errors.New("malformed token header")
	}
	var header struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil || header.Typ != "wia+jwt" {
		return nil, "", errors.New("not a wia+jwt")
	}

	// Signature + expiry against the wallet-provider key (h.issuer signs
	// every WIA; VerifyAccessToken validates exp).
	claims, err := h.issuer.VerifyAccessToken(tokenStr)
	if err != nil {
		return nil, "", err
	}

	cnf, _ := claims["cnf"].(map[string]interface{})
	jwk, _ := cnf["jwk"].(map[string]interface{})
	if jwk == nil {
		return nil, "", errors.New("wia carries no cnf.jwk holder key")
	}
	pub, raw, err := ecdsaFromJWK(jwk)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return pub, base64.RawURLEncoding.EncodeToString(sum[:8]), nil
}

// ecdsaFromJWK reconstructs a P-256 public key from the minimal EC JWK shape
// IssueWIA embeds (tokens.ECPublicJWK), returning the parsed key and the
// SEC1 uncompressed point bytes.
func ecdsaFromJWK(jwk map[string]interface{}) (*ecdsa.PublicKey, []byte, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	if kty != "EC" || crv != "P-256" {
		return nil, nil, errors.New("holder key is not an EC P-256 JWK")
	}
	xs, _ := jwk["x"].(string)
	ys, _ := jwk["y"].(string)
	xb, err := base64.RawURLEncoding.DecodeString(xs)
	if err != nil || len(xb) != 32 {
		return nil, nil, errors.New("holder key x coordinate invalid")
	}
	yb, err := base64.RawURLEncoding.DecodeString(ys)
	if err != nil || len(yb) != 32 {
		return nil, nil, errors.New("holder key y coordinate invalid")
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, nil, errors.New("holder key is not on P-256")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	raw := elliptic.Marshal(elliptic.P256(), x, y)
	return pub, raw, nil
}
