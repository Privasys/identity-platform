package federation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/idp/internal/social"
)

type memStore map[string]string

func (m memStore) FederationOf(id string) (string, error)     { return m[id], nil }
func (m memStore) SetFederation(id, raw string) error         { m[id] = raw; return nil }
func (m memStore) AllFederations() (map[string]string, error) { return m, nil }

type memKeys struct {
	keys      map[string]*rsa.PrivateKey
	destroyed []string
}

func newMemKeys() *memKeys { return &memKeys{keys: map[string]*rsa.PrivateKey{}} }

func (k *memKeys) CreateSigningKey(_ context.Context, name string) (string, *rsa.PublicKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, err
	}
	ref := "ref/" + name
	k.keys[ref] = key
	return ref, &key.PublicKey, nil
}
func (k *memKeys) Sign(_ context.Context, ref string, digest []byte) ([]byte, error) {
	key, ok := k.keys[ref]
	if !ok {
		return nil, fmt.Errorf("no key %s", ref)
	}
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
}
func (k *memKeys) DestroySigningKey(_ context.Context, ref string) error {
	k.destroyed = append(k.destroyed, ref)
	delete(k.keys, ref)
	return nil
}
func (k *memKeys) Wrap(_ context.Context, p []byte) ([]byte, error) {
	return append([]byte("w:"), p...), nil
}
func (k *memKeys) Unwrap(_ context.Context, w []byte) ([]byte, error) {
	return []byte(strings.TrimPrefix(string(w), "w:")), nil
}

func certRequest() SetRequest {
	var r SetRequest
	r.ClientID, r.Tenant, r.DisplayName = "upstream-id", "contoso.example", "Contoso"
	r.Credential.Kind = KindCertificate
	return r
}

var ctx = context.Background()

func parseCert(t *testing.T, p string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		t.Fatal("no PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCertificateCredential(t *testing.T) {
	store, keys := memStore{}, newMemKeys()
	s := NewService(store, keys)
	v, err := s.Set(ctx, "c1", "microsoft", certRequest())
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, v.Certificate)
	if err := cert.CheckSignatureFrom(cert); err != nil {
		// A self-signed leaf is not a CA, so check the signature itself.
		if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
			t.Fatalf("self-signed by the KMS key: %v", err)
		}
	}
	if got := time.Until(cert.NotAfter); got < 729*24*time.Hour || got > 731*24*time.Hour {
		t.Fatalf("lifetime %v, want two years", got)
	}
	if v.ExpiresAt == nil || !v.ExpiresAt.Equal(cert.NotAfter) {
		t.Fatalf("expiry %v, certificate %v", v.ExpiresAt, cert.NotAfter)
	}
	if strings.Contains(store["c1"], "PRIVATE") {
		t.Fatal("a private key reached the table")
	}

	base := &social.Provider{Name: "microsoft", ClientID: "platform", ClientSecret: "platform-secret", UserInfoURL: "https://graph.microsoft.com/v1.0/me", PKCE: true}
	p, err := s.ProviderFor("c1", "microsoft", base)
	if err != nil || p == nil {
		t.Fatalf("provider: %v %v", p, err)
	}
	if p.ClientID != "upstream-id" || p.ClientSecret != "" || p.DisplayName != "Contoso" {
		t.Fatalf("provider: %+v", p)
	}
	if p.TokenURL != "https://login.microsoftonline.com/contoso.example/oauth2/v2.0/token" || p.UserInfoURL != base.UserInfoURL {
		t.Fatalf("endpoints: %s %s", p.TokenURL, p.UserInfoURL)
	}
	if base.ClientID != "platform" {
		t.Fatal("the platform's provider must not change")
	}

	form := url.Values{}
	if err := p.Credential(ctx, form); err != nil {
		t.Fatal(err)
	}
	if form.Get("client_secret") != "" {
		t.Fatalf("form: %v", form)
	}
	if form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("assertion type: %q", form.Get("client_assertion_type"))
	}
	parts := strings.Split(form.Get("client_assertion"), ".")
	if len(parts) != 3 {
		t.Fatal("not a JWT")
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("the assertion must verify against the uploaded certificate: %v", err)
	}
	var hdr, claims map[string]any
	rawHdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	rawClaims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(rawHdr, &hdr)
	json.Unmarshal(rawClaims, &claims)
	if hdr["alg"] != "RS256" || hdr["x5t"] == "" {
		t.Fatalf("header: %v", hdr)
	}
	if claims["iss"] != "upstream-id" || claims["sub"] != "upstream-id" || claims["aud"] != p.TokenURL {
		t.Fatalf("claims: %v", claims)
	}
}

func TestRotationKeepsTheOldKeyUntilConfirmed(t *testing.T) {
	store, keys := memStore{}, newMemKeys()
	s := NewService(store, keys)
	first, _ := s.Set(ctx, "c1", "microsoft", certRequest())
	entries, _ := s.entries("c1")
	oldRef := entries["microsoft"].Credential.Certificate.KeyRef

	second, err := s.Set(ctx, "c1", "microsoft", certRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !second.RotationPending || second.Certificate == first.Certificate {
		t.Fatalf("the rotation must return a new certificate: %+v", second)
	}
	entries, _ = s.entries("c1")
	if entries["microsoft"].Credential.Certificate.KeyRef != oldRef {
		t.Fatal("the old key must keep signing until the upload is confirmed")
	}
	if len(keys.destroyed) != 0 {
		t.Fatal("nothing is destroyed before the confirmation")
	}

	// Rotating again before confirming drops only the unconfirmed key.
	third, _ := s.Set(ctx, "c1", "microsoft", certRequest())
	if len(keys.destroyed) != 1 || keys.destroyed[0] == oldRef {
		t.Fatalf("destroyed: %v", keys.destroyed)
	}

	v, err := s.Confirm(ctx, "c1", "microsoft")
	if err != nil {
		t.Fatal(err)
	}
	if v.RotationPending || v.Certificate != third.Certificate {
		t.Fatalf("confirmed view: %+v", v)
	}
	if keys.destroyed[len(keys.destroyed)-1] != oldRef {
		t.Fatalf("the old key goes on confirmation: %v", keys.destroyed)
	}
	if _, err := s.Confirm(ctx, "c1", "microsoft"); err == nil {
		t.Fatal("nothing left to confirm")
	}
}

func TestSecretCredentialIsWrappedAndNeverListed(t *testing.T) {
	store, keys := memStore{}, newMemKeys()
	s := NewService(store, keys)
	req := certRequest()
	req.Credential.Kind, req.Credential.Secret = KindSecret, "s3cret-value"
	v, err := s.Set(ctx, "c1", "microsoft", req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), "s3cret") || strings.Contains(store["c1"], "s3cret") {
		t.Fatalf("the secret leaked: %s / %s", raw, store["c1"])
	}
	listed, _ := s.List("c1")
	raw, _ = json.Marshal(listed)
	if strings.Contains(string(raw), "wrapped") || strings.Contains(string(raw), "key_ref") {
		t.Fatalf("listing carries credential material: %s", raw)
	}
	p, _ := s.ProviderFor("c1", "microsoft", &social.Provider{Name: "microsoft"})
	form := url.Values{}
	if err := p.Credential(ctx, form); err != nil {
		t.Fatal(err)
	}
	if form.Get("client_secret") != "s3cret-value" {
		t.Fatalf("form: %v", form)
	}
}

func TestDeleteAndValidation(t *testing.T) {
	store, keys := memStore{}, newMemKeys()
	s := NewService(store, keys)
	if _, err := s.Set(ctx, "c1", "microsoft", certRequest()); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "c1", "microsoft"); err != nil {
		t.Fatal(err)
	}
	if len(keys.keys) != 0 {
		t.Fatal("deleting an entry destroys its key")
	}
	if p, err := s.ProviderFor("c1", "microsoft", &social.Provider{}); p != nil || err != nil {
		t.Fatalf("no entry: %v %v", p, err)
	}

	bad := certRequest()
	bad.Tenant = "../../evil"
	if _, err := s.Set(ctx, "c1", "microsoft", bad); err == nil {
		t.Fatal("a tenant must not reach the URL unchecked")
	}
	if _, err := s.Set(ctx, "c1", "github", certRequest()); err == nil {
		t.Fatal("only microsoft for now")
	}
	bad = certRequest()
	bad.Credential.Kind = "federated"
	if _, err := s.Set(ctx, "c1", "microsoft", bad); err == nil {
		t.Fatal("the federated kind is not built yet")
	}
	if _, err := NewService(store, nil).Set(ctx, "c1", "microsoft", certRequest()); !errors.Is(err, ErrNoKeyService) {
		t.Fatalf("no key service: %v", err)
	}

	// A broken entry is an error, never the platform's registration instead.
	store["c2"] = "{not json"
	if _, err := s.ProviderFor("c2", "microsoft", &social.Provider{}); err == nil {
		t.Fatal("a broken entry must not fall back")
	}
}

func TestExpiriesAndDisplayNames(t *testing.T) {
	store, keys := memStore{}, newMemKeys()
	s := NewService(store, keys)
	s.Set(ctx, "c1", "microsoft", certRequest())
	out, err := s.Expiries()
	if err != nil || len(out) != 1 || out[0].Client != "c1" {
		t.Fatalf("expiries: %v %v", out, err)
	}
	if s.DisplayNames("c1")["microsoft"] != "Contoso" {
		t.Fatalf("names: %v", s.DisplayNames("c1"))
	}
}

// Only a registration on a named tenant answers for the addresses it returns.
func TestOwnDirectoryVouchesForEmail(t *testing.T) {
	s := NewService(memStore{}, newMemKeys())
	for tenant, want := range map[string]bool{"contoso.example": true, "0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b": true, "common": false, "Organizations": false, "consumers": false} {
		req := certRequest()
		req.Tenant = tenant
		if err := s.Delete(ctx, "c1", "microsoft"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Set(ctx, "c1", "microsoft", req); err != nil {
			t.Fatal(err)
		}
		p, err := s.ProviderFor("c1", "microsoft", &social.Provider{Name: "microsoft"})
		if err != nil {
			t.Fatal(err)
		}
		if p.VouchesEmail != want {
			t.Errorf("%s: vouches %v, want %v", tenant, p.VouchesEmail, want)
		}
	}
}
