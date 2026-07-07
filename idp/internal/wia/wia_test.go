// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package wia

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/Privasys/idp/internal/tokens"
)

func newTestHandler(t *testing.T, mode string) (*Handler, *tokens.Issuer) {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "wia-key.pem")
	iss, err := tokens.NewIssuer(keyPath, "https://privasys.id/wallet-provider")
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	h := New(Config{
		Issuer:   iss,
		Resolver: func(tok string) (string, bool) { return "user-1", tok == "good" },
		Policy:   AttestPolicy{Mode: mode, AndroidAllowTEE: true},
		TTL:      48 * time.Hour,
	})
	return h, iss
}

func post(h http.HandlerFunc, path, bearer string, body interface{}) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest("POST", path, strings.NewReader(string(b)))
	} else {
		r = httptest.NewRequest("POST", path, nil)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer wallet:"+bearer)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func getChallenge(t *testing.T, h *Handler) []byte {
	t.Helper()
	w := post(h.HandleChallenge, "/wia/challenge", "good", nil)
	if w.Code != 200 {
		t.Fatalf("challenge: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Challenge string `json:"challenge"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	b, err := base64.RawURLEncoding.DecodeString(out.Challenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	// Return the b64url form too via a closure-free trick: store on the store.
	t.Cleanup(func() {})
	challengeB64 = out.Challenge
	return b
}

var challengeB64 string

func holderPubB64(k *ecdsa.PrivateKey) (string, []byte) {
	raw := elliptic.Marshal(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
	return base64.RawURLEncoding.EncodeToString(raw), raw
}

func popSig(t *testing.T, k *ecdsa.PrivateKey, challenge []byte) string {
	t.Helper()
	digest := sha256.Sum256(challenge)
	der, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

// ── proof of possession ───────────────────────────────────────────────────

func TestHolderPoP(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	challenge := []byte("a-fresh-challenge")
	digest := sha256.Sum256(challenge)
	der, _ := ecdsa.SignASN1(rand.Reader, k, digest[:])
	if err := verifyHolderPoP(&k.PublicKey, challenge, der); err != nil {
		t.Fatalf("valid PoP rejected: %v", err)
	}
	// A signature by a different key must fail.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := verifyHolderPoP(&other.PublicKey, challenge, der); err == nil {
		t.Fatal("PoP accepted a signature from the wrong key")
	}
}

// ── issuance ──────────────────────────────────────────────────────────────

func TestIssueWIABindsHolder(t *testing.T) {
	_, iss := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := tokens.ECPublicJWK(&holder.PublicKey)
	tok, err := iss.IssueWIA(tokens.WIAClaims{HolderJWK: jwk, Level: "strongbox", Platform: "android", TTL: time.Hour})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	parsed, err := jwt.Parse(tok, func(*jwt.Token) (interface{}, error) { return iss.PublicKey(), nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Header["typ"] != "wia+jwt" {
		t.Fatalf("typ = %v, want wia+jwt", parsed.Header["typ"])
	}
	claims := parsed.Claims.(jwt.MapClaims)
	cnf := claims["cnf"].(map[string]interface{})
	got := cnf["jwk"].(map[string]interface{})
	if got["x"] != jwk["x"] || got["y"] != jwk["y"] || got["crv"] != "P-256" {
		t.Fatalf("cnf.jwk did not round-trip: %v", got)
	}
}

// ── Android keystore enrolment ────────────────────────────────────────────

func buildAndroidLeaf(t *testing.T, holder *ecdsa.PrivateKey, challenge []byte, secLevel int) string {
	t.Helper()
	kd := keyDescription{
		AttestationVersion:       3,
		AttestationSecurityLevel: asn1.Enumerated(secLevel),
		KeymasterVersion:         4,
		KeymasterSecurityLevel:   asn1.Enumerated(secLevel),
		AttestationChallenge:     challenge,
		UniqueID:                 []byte{},
		SoftwareEnforced:         asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
		TeeEnforced:              asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
	}
	kdDER, err := asn1.Marshal(kd)
	if err != nil {
		t.Fatalf("marshal KeyDescription: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidAndroidKeyAttestation, Value: kdDER}},
	}
	// Self-signed with the holder key: leaf public key == holder key (soft mode
	// does not verify the chain, only the leaf-key + challenge binding).
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &holder.PublicKey, holder)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestEnrolAndroidKeystoreSoft(t *testing.T) {
	h, iss := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	challenge := getChallenge(t, h)
	hpB64, _ := holderPubB64(holder)
	leaf := buildAndroidLeaf(t, holder, challenge, androidSecurityStrongBox)

	w := post(h.HandleEnrol, "/wia/enrol", "good", enrolRequest{
		Platform:    "android",
		HolderPub:   hpB64,
		Challenge:   challengeB64,
		HolderSig:   popSig(t, holder, challenge),
		Attestation: Attestation{ChainB64: []string{leaf}},
	})
	if w.Code != 200 {
		t.Fatalf("enrol: %d %s", w.Code, w.Body.String())
	}
	var out enrolResponse
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Level != "strongbox" {
		t.Fatalf("level = %q, want strongbox", out.Level)
	}
	// The issued WIA verifies under the wallet-provider key and binds the holder.
	parsed, err := jwt.Parse(out.WIA, func(*jwt.Token) (interface{}, error) { return iss.PublicKey(), nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("WIA invalid: %v", err)
	}
	cnf := parsed.Claims.(jwt.MapClaims)["cnf"].(map[string]interface{})["jwk"].(map[string]interface{})
	if cnf["x"] != tokens.ECPublicJWK(&holder.PublicKey)["x"] {
		t.Fatal("WIA cnf.jwk does not match holder")
	}
}

func TestEnrolRejectsWrongHolderInChain(t *testing.T) {
	h, _ := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKeyInCert, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	challenge := getChallenge(t, h)
	hpB64, _ := holderPubB64(holder)
	// Attestation certifies a DIFFERENT key than the holder we present.
	leaf := buildAndroidLeaf(t, otherKeyInCert, challenge, androidSecurityStrongBox)

	w := post(h.HandleEnrol, "/wia/enrol", "good", enrolRequest{
		Platform:    "android",
		HolderPub:   hpB64,
		Challenge:   challengeB64,
		HolderSig:   popSig(t, holder, challenge),
		Attestation: Attestation{ChainB64: []string{leaf}},
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d %s", w.Code, w.Body.String())
	}
}

func TestEnrolRejectsChallengeReplay(t *testing.T) {
	h, _ := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	challenge := getChallenge(t, h)
	hpB64, _ := holderPubB64(holder)
	leaf := buildAndroidLeaf(t, holder, challenge, androidSecurityStrongBox)
	req := enrolRequest{
		Platform:    "android",
		HolderPub:   hpB64,
		Challenge:   challengeB64,
		HolderSig:   popSig(t, holder, challenge),
		Attestation: Attestation{ChainB64: []string{leaf}},
	}
	if w := post(h.HandleEnrol, "/wia/enrol", "good", req); w.Code != 200 {
		t.Fatalf("first enrol: %d %s", w.Code, w.Body.String())
	}
	// The challenge is single-use: the same request must now fail.
	if w := post(h.HandleEnrol, "/wia/enrol", "good", req); w.Code != http.StatusBadRequest {
		t.Fatalf("replay expected 400, got %d", w.Code)
	}
}

func TestEnrolRequiresWalletSession(t *testing.T) {
	h, _ := newTestHandler(t, "soft")
	if w := post(h.HandleChallenge, "/wia/challenge", "bad", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("challenge without valid session expected 401, got %d", w.Code)
	}
}

// ── iOS App Attest enrolment ──────────────────────────────────────────────

func buildAppAttest(t *testing.T, challenge, holderRaw []byte) string {
	t.Helper()
	authData := make([]byte, 37)
	if _, err := rand.Read(authData); err != nil {
		t.Fatal(err)
	}
	clientData := append(append([]byte{}, challenge...), holderRaw...)
	cdh := sha256.Sum256(clientData)
	composite := append(append([]byte{}, authData...), cdh[:]...)
	nonce := sha256.Sum256(composite)

	nonceExt, err := asn1.Marshal(struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}{nonce[:]})
	if err != nil {
		t.Fatalf("marshal nonce: %v", err)
	}
	credKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "App Attest Cred"},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidAppleAppAttestNonce, Value: nonceExt}},
	}
	credDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &credKey.PublicKey, credKey)
	if err != nil {
		t.Fatalf("cred cert: %v", err)
	}

	var obj appAttestObject
	obj.Fmt = "apple-appattest"
	obj.AttStmt.X5c = [][]byte{credDER}
	obj.AuthData = authData
	enc, err := cbor.Marshal(&obj)
	if err != nil {
		t.Fatalf("cbor: %v", err)
	}
	return base64.StdEncoding.EncodeToString(enc)
}

func TestEnrolAppAttestSoft(t *testing.T) {
	h, iss := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	challenge := getChallenge(t, h)
	hpB64, holderRaw := holderPubB64(holder)
	attObj := buildAppAttest(t, challenge, holderRaw)

	w := post(h.HandleEnrol, "/wia/enrol", "good", enrolRequest{
		Platform:    "ios",
		HolderPub:   hpB64,
		Challenge:   challengeB64,
		HolderSig:   popSig(t, holder, challenge),
		Attestation: Attestation{KeyID: "k1", AttObjectB64: attObj},
	})
	if w.Code != 200 {
		t.Fatalf("enrol: %d %s", w.Code, w.Body.String())
	}
	var out enrolResponse
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Level != "app-attest" {
		t.Fatalf("level = %q, want app-attest", out.Level)
	}
	if _, err := jwt.Parse(out.WIA, func(*jwt.Token) (interface{}, error) { return iss.PublicKey(), nil }); err != nil {
		t.Fatalf("WIA invalid: %v", err)
	}
}

func TestEnrolAppAttestRejectsHolderTamper(t *testing.T) {
	h, _ := newTestHandler(t, "soft")
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	challenge := getChallenge(t, h)
	_, holderRaw := holderPubB64(holder)
	// App Attest binds `holder`, but the request presents the attacker's key.
	attObj := buildAppAttest(t, challenge, holderRaw)
	attackerB64, _ := holderPubB64(attacker)

	w := post(h.HandleEnrol, "/wia/enrol", "good", enrolRequest{
		Platform:    "ios",
		HolderPub:   attackerB64,
		Challenge:   challengeB64,
		HolderSig:   popSig(t, attacker, challenge),
		Attestation: Attestation{KeyID: "k1", AttObjectB64: attObj},
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (nonce binds a different key), got %d %s", w.Code, w.Body.String())
	}
}
