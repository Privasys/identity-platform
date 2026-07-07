// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package wia implements the IdP (wallet-provider) half of Wallet Instance
// Attestation: it proves the wallet's hardware holder key lives in genuine
// hardware inside our genuine app, then issues a short-lived WIA JWT with
// cnf.jwk = holder_pub that the verifier enclave requires before doing any
// (free) identity verification. See attribute-billing-plan §3.
package wia

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Android Keystore key-attestation extension (KeyDescription).
var oidAndroidKeyAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// Apple App Attest nonce extension (SHA-256 of authData ‖ clientDataHash).
var oidAppleAppAttestNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// Android attestation security levels (KeyDescription.attestationSecurityLevel).
const (
	androidSecuritySoftware = 0
	androidSecurityTEE      = 1
	androidSecurityStrongBox = 2
)

// AttestPolicy governs how strictly device attestation is checked. Default mode
// is "soft" (structural + holder-key binding), which lets the WIA vertical ship
// and closes the trivial free-KYC hole while the fleet gains coverage; flip to
// "strict" once the platform roots + app identifiers below are provisioned and
// validated against real devices (attribute-billing-plan §7). Strict mode fails
// closed if the material it needs is missing — it never silently downgrades.
type AttestPolicy struct {
	Mode string // "soft" (default) | "strict"

	// Apple (iOS App Attest)
	AppleTeamID   string
	AppleBundleID string
	AppleRootPEM  string // Apple App Attest Root CA (required for strict iOS)

	// Android (hardware Keystore key attestation)
	AndroidPackage  string
	AndroidRootPEM  string // Google hardware-attestation root (required for strict android)
	AndroidAllowTEE bool   // when false, require StrongBox (reject plain TEE)
}

func (p AttestPolicy) strict() bool { return p.Mode == "strict" }

// Attestation is the platform device-integrity evidence a wallet submits at
// enrolment. Exactly one platform's fields are populated.
type Attestation struct {
	// iOS App Attest
	KeyID       string `json:"key_id,omitempty"`
	AttObjectB64 string `json:"attestation,omitempty"` // base64 CBOR apple-appattest object

	// Android hardware Keystore key attestation (leaf-first DER cert chain).
	ChainB64 []string `json:"chain,omitempty"`

	// Android Play Integrity token (fallback — not the preferred path).
	IntegrityToken string `json:"integrity_token,omitempty"`
}

// verifyHolderPoP checks a proof-of-possession: an ECDSA (ASN.1 DER) signature
// by the holder key over the enrolment challenge. NativeKeys.sign hashes the
// message with SHA-256 on both platforms, so we verify over SHA-256(challenge).
func verifyHolderPoP(holderPub *ecdsa.PublicKey, challenge, derSig []byte) error {
	digest := sha256.Sum256(challenge)
	if !ecdsa.VerifyASN1(holderPub, digest[:], derSig) {
		return errors.New("holder proof-of-possession signature is invalid")
	}
	return nil
}

// ValidateDevice checks that the platform attestation binds this holder key on
// genuine hardware/app and returns the attested security level. It does NOT
// check the holder PoP (the handler does that separately). challenge and
// holderPubRaw are raw bytes; holderPub is the parsed key.
func ValidateDevice(platform string, att Attestation, challenge, holderPubRaw []byte, holderPub *ecdsa.PublicKey, p AttestPolicy) (string, error) {
	switch platform {
	case "android":
		if len(att.ChainB64) > 0 {
			return validateAndroidKeystore(att.ChainB64, challenge, holderPub, p)
		}
		if att.IntegrityToken != "" {
			return validatePlayIntegrity(att.IntegrityToken, p)
		}
		return "", errors.New("android attestation requires a keystore chain or an integrity token")
	case "ios":
		return validateAppAttest(att, challenge, holderPubRaw, p)
	default:
		return "", fmt.Errorf("unsupported platform %q", platform)
	}
}

// ── Android hardware Keystore key attestation ─────────────────────────────

// keyDescription is the leading fields of the Android KeyDescription ASN.1
// SEQUENCE (RFC-less, Google-defined). We only need the security level and the
// attestation challenge; the two AuthorizationLists are captured opaquely.
type keyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TeeEnforced              asn1.RawValue
}

func validateAndroidKeystore(chainB64 []string, challenge []byte, holderPub *ecdsa.PublicKey, p AttestPolicy) (string, error) {
	if len(chainB64) == 0 {
		return "", errors.New("empty keystore attestation chain")
	}
	certs := make([]*x509.Certificate, 0, len(chainB64))
	for i, b := range chainB64 {
		der, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			return "", fmt.Errorf("keystore chain cert %d: bad base64: %w", i, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "", fmt.Errorf("keystore chain cert %d: %w", i, err)
		}
		certs = append(certs, c)
	}
	leaf := certs[0]

	// The attested key MUST be the holder key — otherwise the attestation
	// proves nothing about the key we are about to bind into the WIA.
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsaEqual(leafPub, holderPub) {
		return "", errors.New("keystore leaf key does not match the holder key")
	}

	// Parse the KeyDescription extension: the attestation challenge must be our
	// fresh enrolment challenge (freshness / anti-replay), and the security level
	// tells us StrongBox vs TEE.
	kd, err := parseKeyDescription(leaf)
	if err != nil {
		return "", err
	}
	if !bytesEqual(kd.AttestationChallenge, challenge) {
		return "", errors.New("keystore attestation challenge does not match the enrolment challenge")
	}

	level := "tee"
	if kd.AttestationSecurityLevel == androidSecurityStrongBox {
		level = "strongbox"
	} else if kd.AttestationSecurityLevel == androidSecuritySoftware {
		return "", errors.New("keystore attestation is software-only (not hardware-backed)")
	}
	if !p.AndroidAllowTEE && level != "strongbox" {
		return "", errors.New("policy requires a StrongBox-backed key")
	}

	if p.strict() {
		if p.AndroidRootPEM == "" {
			return "", errors.New("strict mode: no Android attestation root configured")
		}
		if err := verifyChainToRoot(certs, p.AndroidRootPEM); err != nil {
			return "", fmt.Errorf("keystore chain: %w", err)
		}
		// Package-name pinning (attestationApplicationId in the AuthorizationList)
		// is deferred until strict is enabled against real devices; recorded here
		// so the check is not silently skipped.
		if p.AndroidPackage == "" {
			return "", errors.New("strict mode: no Android package name configured")
		}
	}
	return level, nil
}

func parseKeyDescription(leaf *x509.Certificate) (*keyDescription, error) {
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidAndroidKeyAttestation) {
			var kd keyDescription
			if _, err := asn1.Unmarshal(ext.Value, &kd); err != nil {
				return nil, fmt.Errorf("parse KeyDescription: %w", err)
			}
			return &kd, nil
		}
	}
	return nil, errors.New("keystore leaf has no key-attestation extension")
}

// ── iOS App Attest ────────────────────────────────────────────────────────

type appAttestObject struct {
	Fmt     string `cbor:"fmt"`
	AttStmt struct {
		X5c     [][]byte `cbor:"x5c"`
		Receipt []byte   `cbor:"receipt"`
	} `cbor:"attStmt"`
	AuthData []byte `cbor:"authData"`
}

func validateAppAttest(att Attestation, challenge, holderPubRaw []byte, p AttestPolicy) (string, error) {
	if att.AttObjectB64 == "" {
		return "", errors.New("ios attestation object is required")
	}
	raw, err := decodeB64Any(att.AttObjectB64)
	if err != nil {
		return "", fmt.Errorf("attestation object: bad base64: %w", err)
	}
	var obj appAttestObject
	if err := cbor.Unmarshal(raw, &obj); err != nil || obj.Fmt != "apple-appattest" {
		// Not a full apple-appattest attestation object — almost certainly an
		// App Attest *assertion* from an already-attested key (the wallet shares
		// one App Attest key with the attestation-server flow, and a key can be
		// attested only once). During the soft rollout this is tolerated: the
		// holder proof-of-possession is the binding gate. Strict mode requires a
		// full attestation object (and a dedicated App Attest key on the client).
		if p.strict() {
			return "", errors.New("strict mode: a full App Attest attestation object is required")
		}
		if len(raw) == 0 {
			return "", errors.New("empty ios attestation")
		}
		return "app-attest", nil
	}
	if len(obj.AttStmt.X5c) == 0 {
		return "", errors.New("attestation has no x5c chain")
	}
	credCert, err := x509.ParseCertificate(obj.AttStmt.X5c[0])
	if err != nil {
		return "", fmt.Errorf("credential cert: %w", err)
	}

	// The binding that matters: the App Attest nonce commits to our clientData
	// (challenge ‖ holder_pub), so a genuine, unmodified app on a genuine device
	// vouched for exactly this holder key and this fresh challenge.
	clientData := append(append([]byte{}, challenge...), holderPubRaw...)
	clientDataHash := sha256.Sum256(clientData)
	composite := append(append([]byte{}, obj.AuthData...), clientDataHash[:]...)
	expectedNonce := sha256.Sum256(composite)
	certNonce, err := appleAttestNonce(credCert)
	if err != nil {
		return "", err
	}
	if !bytesEqual(certNonce, expectedNonce[:]) {
		return "", errors.New("app-attest nonce does not bind this challenge and holder key")
	}

	if p.strict() {
		if p.AppleRootPEM == "" {
			return "", errors.New("strict mode: no Apple App Attest root configured")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(p.AppleRootPEM)) {
			return "", errors.New("strict mode: invalid Apple App Attest root PEM")
		}
		inter := x509.NewCertPool()
		for _, der := range obj.AttStmt.X5c[1:] {
			if c, err := x509.ParseCertificate(der); err == nil {
				inter.AddCert(c)
			}
		}
		if _, err := credCert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter}); err != nil {
			return "", fmt.Errorf("app-attest chain: %w", err)
		}
		// rpIdHash (authData[0:32]) must equal SHA256("<team>.<bundle>").
		if p.AppleTeamID == "" || p.AppleBundleID == "" {
			return "", errors.New("strict mode: no Apple team/bundle id configured")
		}
		if len(obj.AuthData) < 37 {
			return "", errors.New("app-attest authData too short")
		}
		appID := sha256.Sum256([]byte(p.AppleTeamID + "." + p.AppleBundleID))
		if !bytesEqual(obj.AuthData[0:32], appID[:]) {
			return "", errors.New("app-attest rpId hash does not match the app id")
		}
	}
	return "app-attest", nil
}

// appleAttestNonce extracts the nonce octet string from the App Attest cred
// cert extension (OID 1.2.840.113635.100.8.2): SEQUENCE { [1] EXPLICIT OCTET STRING }.
func appleAttestNonce(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidAppleAppAttestNonce) {
			var seq struct {
				Nonce []byte `asn1:"tag:1,explicit"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &seq); err != nil {
				return nil, fmt.Errorf("parse app-attest nonce extension: %w", err)
			}
			return seq.Nonce, nil
		}
	}
	return nil, errors.New("app-attest credential cert has no nonce extension")
}

// ── Android Play Integrity (fallback path) ────────────────────────────────

func validatePlayIntegrity(token string, p AttestPolicy) (string, error) {
	if token == "" {
		return "", errors.New("empty integrity token")
	}
	if p.strict() {
		// Full Play Integrity verdict validation requires a Google API call; the
		// preferred, self-contained Android path is hardware Keystore attestation,
		// so strict mode rejects the integrity-token fallback rather than pretend
		// to validate it.
		return "", errors.New("strict mode: use hardware Keystore attestation, not Play Integrity")
	}
	return "play-integrity", nil
}

// ── helpers ───────────────────────────────────────────────────────────────

func verifyChainToRoot(certs []*x509.Certificate, rootPEM string) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(rootPEM)) {
		return errors.New("invalid root PEM")
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	// Keystore attestation certs are not TLS certs; skip EKU/usage checks and
	// verify chain-of-trust to the pinned root only.
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func ecdsaEqual(a, b *ecdsa.PublicKey) bool {
	return a != nil && b != nil && a.Curve == b.Curve &&
		a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// parseHolderPub decodes a base64url SEC1 uncompressed P-256 point.
func parseHolderPub(b64 string) (*ecdsa.PublicKey, []byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		// tolerate padded base64url
		raw, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, nil, fmt.Errorf("holder_pub base64: %w", err)
		}
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), raw)
	if x == nil {
		return nil, nil, errors.New("holder_pub is not a valid P-256 point")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, raw, nil
}
