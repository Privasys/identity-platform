package federation

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // x5t is defined as a SHA-1 thumbprint; it names a certificate, it protects nothing.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Privasys/idp/internal/social"
)

const (
	// KindCertificate is a certificate credential: the token exchange is
	// signed by a key generated here. Nothing is shared.
	KindCertificate = "certificate"
	// KindSecret is a client secret the customer hands over, kept wrapped.
	KindSecret = "secret"

	// ModeReplace: the client's own registration stands in for the
	// platform's for this provider, for every user of the client.
	// ModeBeside: it is offered as a button of its own, and the platform's
	// registration stays on the gate for everyone else.
	ModeReplace = "replace"
	ModeBeside  = "beside"

	certificateLifetime = 2 * 365 * 24 * time.Hour
	assertionLifetime   = 5 * time.Minute
)

var tenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,99}$`)

// validIconURL accepts the address of the icon a client's gate draws on its
// button: https only, no credentials, short. The frame renders it as an
// image, never as markup, so the address is the whole exposure.
func validIconURL(raw string) error {
	if raw == "" {
		return nil
	}
	if len(raw) > 512 {
		return errors.New("icon_url is limited to 512 characters")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("icon_url must be an https address")
	}
	return nil
}

// Certificate is one generated key pair and its public certificate.
type Certificate struct {
	KeyRef     string    `json:"key_ref"`
	PEM        string    `json:"certificate_pem"`
	Thumbprint string    `json:"x5t"`
	NotAfter   time.Time `json:"not_after"`
}

// Credential is how the identity provider authenticates to the upstream token
// endpoint. Pending is a rotated certificate the customer has not yet confirmed
// uploading: until they do, sign-ins keep using the current one.
type Credential struct {
	Kind          string       `json:"kind"`
	Certificate   *Certificate `json:"certificate,omitempty"`
	Pending       *Certificate `json:"pending,omitempty"`
	WrappedSecret string       `json:"wrapped_secret,omitempty"`
}

// Entry is a client's own registration with one provider.
type Entry struct {
	ClientID    string     `json:"client_id"`
	Tenant      string     `json:"tenant"`
	DisplayName string     `json:"display_name,omitempty"`
	IconURL     string     `json:"icon_url,omitempty"`
	Mode        string     `json:"mode,omitempty"`
	Credential  Credential `json:"credential"`
}

// Active says the entry names a registration and serves sign-ins. An entry
// prepared before the registration exists holds a certificate and nothing
// else: the platform's registration serves until the ids are set.
func (e *Entry) Active() bool { return e.ClientID != "" }

// Beside says the entry is a button of its own next to the platform's
// registration rather than a replacement for it.
func (e *Entry) Beside() bool { return e.Mode == ModeBeside }

// SetRequest is what the admin route accepts. Secret is taken once.
type SetRequest struct {
	ClientID    string `json:"client_id"`
	Tenant      string `json:"tenant"`
	DisplayName string `json:"display_name"`
	IconURL     string `json:"icon_url,omitempty"`
	Mode        string `json:"mode,omitempty"` // replace (default) or beside
	Credential  struct {
		Kind   string `json:"kind"`
		Secret string `json:"secret,omitempty"`
		Rotate bool   `json:"rotate,omitempty"` // generate a new key pair although one exists
	} `json:"credential"`
}

// View is an entry as a listing shows it: no key reference, no secret.
type View struct {
	Provider        string     `json:"provider"`
	ClientID        string     `json:"client_id"`
	Tenant          string     `json:"tenant"`
	DisplayName     string     `json:"display_name,omitempty"`
	IconURL         string     `json:"icon_url,omitempty"`
	Mode            string     `json:"mode"`
	Kind            string     `json:"credential_kind"`
	Active          bool       `json:"active"`                // false until the registration's ids are set
	Certificate     string     `json:"certificate,omitempty"` // the one to upload
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	RotationPending bool       `json:"rotation_pending,omitempty"`
}

// Store keeps each client's entries as one JSON document.
type Store interface {
	FederationOf(clientID string) (string, error)
	SetFederation(clientID, raw string) error
	AllFederations() (map[string]string, error)
}

// Service manages federation entries.
type Service struct {
	store Store
	keys  KeyService
}

// NewService creates a Service. keys may be nil (ResolveKeyService).
func NewService(store Store, keys KeyService) *Service {
	return &Service{store: store, keys: keys}
}

func (s *Service) entries(clientID string) (map[string]*Entry, error) {
	raw, err := s.store.FederationOf(clientID)
	if err != nil {
		return nil, err
	}
	out := map[string]*Entry{}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			return nil, fmt.Errorf("federation of %s: %w", clientID, err)
		}
	}
	return out, nil
}

func (s *Service) save(clientID string, entries map[string]*Entry) error {
	raw, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return s.store.SetFederation(clientID, string(raw))
}

// Set creates or changes a client's entry for a provider. An entry that
// already has a certificate keeps its key, so the ids, name or icon can change
// under a certificate already uploaded; asking to rotate generates a new key
// pair, returned for upload, and the old one keeps signing until Confirm. A
// certificate can be prepared before the registration exists, with no ids:
// the entry then serves nothing until they are set. On an existing entry, a
// field left out keeps its value; Delete is how an entry is cleared.
func (s *Service) Set(ctx context.Context, clientID, provider string, req SetRequest) (*View, error) {
	if provider != "microsoft" {
		return nil, fmt.Errorf("federation is not available for provider %q", provider)
	}
	if len(req.ClientID) > 128 {
		return nil, errors.New("client_id is limited to 128 characters")
	}
	if (req.ClientID == "") != (req.Tenant == "") {
		return nil, errors.New("client_id and tenant go together")
	}
	if req.Tenant != "" && !tenantPattern.MatchString(req.Tenant) {
		return nil, errors.New("tenant must be a tenant id, a verified domain, or common")
	}
	if len(req.DisplayName) > 64 {
		return nil, errors.New("display_name is limited to 64 characters")
	}
	if err := validIconURL(req.IconURL); err != nil {
		return nil, err
	}
	switch req.Mode {
	case "", ModeReplace, ModeBeside:
	default:
		return nil, errors.New("mode must be replace or beside")
	}
	if s.keys == nil {
		return nil, ErrNoKeyService
	}
	entries, err := s.entries(clientID)
	if err != nil {
		return nil, err
	}
	prior := entries[provider]
	entry := &Entry{ClientID: req.ClientID, Tenant: req.Tenant, DisplayName: req.DisplayName, IconURL: req.IconURL, Mode: req.Mode}
	if prior != nil {
		if entry.ClientID == "" {
			entry.ClientID, entry.Tenant = prior.ClientID, prior.Tenant
		}
		if entry.DisplayName == "" {
			entry.DisplayName = prior.DisplayName
		}
		if entry.IconURL == "" {
			entry.IconURL = prior.IconURL
		}
		if entry.Mode == "" {
			entry.Mode = prior.Mode
		}
	}
	if entry.Mode == "" {
		entry.Mode = ModeReplace
	}
	if entry.ClientID == "" && req.Credential.Kind != KindCertificate {
		return nil, errors.New("client_id and tenant are required; only a certificate can be prepared before the registration exists")
	}
	switch req.Credential.Kind {
	case KindCertificate:
		entry.Credential.Kind = KindCertificate
		if prior != nil && prior.Credential.Kind == KindCertificate && prior.Credential.Certificate != nil && !req.Credential.Rotate {
			// The key stays: only the registration's ids, name or icon
			// change, and the certificate already uploaded keeps working.
			entry.Credential.Certificate, entry.Credential.Pending = prior.Credential.Certificate, prior.Credential.Pending
			break
		}
		cert, err := s.generateCertificate(ctx, clientID, provider, entry.ClientID)
		if err != nil {
			return nil, err
		}
		if prior != nil && prior.Credential.Kind == KindCertificate && prior.Credential.Certificate != nil {
			// A rotation: a pending certificate replaced before it was
			// confirmed was never uploaded, so its key can go.
			if prior.Credential.Pending != nil {
				s.destroy(ctx, prior.Credential.Pending.KeyRef)
			}
			entry.Credential.Certificate = prior.Credential.Certificate
			entry.Credential.Pending = cert
		} else {
			entry.Credential.Certificate = cert
		}
	case KindSecret:
		if req.Credential.Secret == "" {
			return nil, errors.New("credential.secret is required for a secret credential")
		}
		wrapped, err := s.seal(ctx, []byte(req.Credential.Secret))
		if err != nil {
			return nil, err
		}
		entry.Credential.Kind = KindSecret
		entry.Credential.WrappedSecret = wrapped
	default:
		return nil, errors.New("credential.kind must be certificate or secret")
	}
	entries[provider] = entry
	if err := s.save(clientID, entries); err != nil {
		return nil, err
	}
	if prior != nil && prior.Credential.Kind == KindCertificate && entry.Credential.Kind != KindCertificate {
		s.destroyAll(ctx, prior)
	}
	v := viewOf(provider, entry)
	return &v, nil
}

// Confirm says the customer has uploaded the rotated certificate: it starts
// signing, and the old key is destroyed.
func (s *Service) Confirm(ctx context.Context, clientID, provider string) (*View, error) {
	entries, err := s.entries(clientID)
	if err != nil {
		return nil, err
	}
	entry := entries[provider]
	if entry == nil || entry.Credential.Pending == nil {
		return nil, errors.New("no rotation is pending")
	}
	old := entry.Credential.Certificate
	entry.Credential.Certificate = entry.Credential.Pending
	entry.Credential.Pending = nil
	if err := s.save(clientID, entries); err != nil {
		return nil, err
	}
	if old != nil {
		s.destroy(ctx, old.KeyRef)
	}
	v := viewOf(provider, entry)
	return &v, nil
}

// Delete removes a client's entry; its users go back to the platform's
// registration.
func (s *Service) Delete(ctx context.Context, clientID, provider string) error {
	entries, err := s.entries(clientID)
	if err != nil {
		return err
	}
	entry := entries[provider]
	if entry == nil {
		return nil
	}
	delete(entries, provider)
	if err := s.save(clientID, entries); err != nil {
		return err
	}
	s.destroyAll(ctx, entry)
	return nil
}

func (s *Service) destroyAll(ctx context.Context, e *Entry) {
	if c := e.Credential.Certificate; c != nil {
		s.destroy(ctx, c.KeyRef)
	}
	if c := e.Credential.Pending; c != nil {
		s.destroy(ctx, c.KeyRef)
	}
}

func (s *Service) destroy(ctx context.Context, ref string) {
	if s.keys == nil {
		return
	}
	if err := s.keys.DestroySigningKey(ctx, ref); err != nil {
		log.Printf("federation: destroy key %s: %v", ref, err)
	}
}

// List shows a client's entries, without key material.
func (s *Service) List(clientID string) ([]View, error) {
	entries, err := s.entries(clientID)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(entries))
	for provider, e := range entries {
		out = append(out, viewOf(provider, e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out, nil
}

// Expiry is one certificate's end date, for the weekly operations check.
type Expiry struct {
	Client    string    `json:"client"`
	Provider  string    `json:"provider"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expiries lists every certificate in use, soonest first.
func (s *Service) Expiries() ([]Expiry, error) {
	all, err := s.store.AllFederations()
	if err != nil {
		return nil, err
	}
	out := []Expiry{}
	for client, raw := range all {
		entries := map[string]*Entry{}
		if err := json.Unmarshal([]byte(raw), &entries); err != nil {
			return nil, fmt.Errorf("federation of %s: %w", client, err)
		}
		for provider, e := range entries {
			if c := e.Credential.Certificate; c != nil {
				out = append(out, Expiry{Client: client, Provider: provider, ExpiresAt: c.NotAfter})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out, nil
}

// Icons gives the icon addresses a client's gate should draw on its buttons.
func (s *Service) Icons(clientID string) map[string]string {
	entries, err := s.entries(clientID)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for provider, e := range entries {
		if e.Active() && !e.Beside() && e.IconURL != "" {
			out[provider] = e.IconURL
		}
	}
	return out
}

// DisplayNames gives the provider names a client's gate should show.
func (s *Service) DisplayNames(clientID string) map[string]string {
	entries, err := s.entries(clientID)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for provider, e := range entries {
		if e.Active() && !e.Beside() && e.DisplayName != "" {
			out[provider] = e.DisplayName
		}
	}
	return out
}

func viewOf(provider string, e *Entry) View {
	mode := e.Mode
	if mode == "" {
		mode = ModeReplace
	}
	v := View{Provider: provider, ClientID: e.ClientID, Tenant: e.Tenant, DisplayName: e.DisplayName, IconURL: e.IconURL, Mode: mode, Kind: e.Credential.Kind, Active: e.Active()}
	cert := e.Credential.Certificate
	if e.Credential.Pending != nil {
		cert = e.Credential.Pending
		v.RotationPending = true
	}
	if cert != nil {
		v.Certificate = cert.PEM
		exp := cert.NotAfter
		v.ExpiresAt = &exp
	}
	return v
}

// Own lists the client's registrations offered as buttons of their own
// (mode beside), for the gate.
func (s *Service) Own(clientID string) []social.OwnRegistration {
	entries, err := s.entries(clientID)
	if err != nil {
		return nil
	}
	out := []social.OwnRegistration{}
	for provider, e := range entries {
		if e.Active() && e.Beside() {
			out = append(out, social.OwnRegistration{Provider: provider, DisplayName: e.DisplayName, IconURL: e.IconURL})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

// ProviderFor gives the upstream registration for a client's users on the
// provider's plain button: the client's own if it replaces the platform's,
// nil otherwise.
func (s *Service) ProviderFor(clientID, provider string, base *social.Provider) (*social.Provider, error) {
	return s.ProviderForRoute(clientID, provider, base, false)
}

// ProviderForRoute gives the upstream registration for a sign-in. own says the
// gate pressed the client's own button: that must be an active entry, never
// the platform's registration in its place. On the plain button the client's
// own entry serves only when it replaces the platform's; an entry beside it,
// a prepared one or none at all leaves the platform's registration (nil). An
// entry that cannot be read is an error, never a silent fall back.
func (s *Service) ProviderForRoute(clientID, provider string, base *social.Provider, own bool) (*social.Provider, error) {
	entries, err := s.entries(clientID)
	if err != nil {
		return nil, err
	}
	entry := entries[provider]
	if entry == nil || !entry.Active() {
		if own {
			return nil, errors.New("this client has no registration of its own for " + provider)
		}
		return nil, nil
	}
	if entry.Beside() && !own {
		return nil, nil
	}
	p := *base
	p.ClientID = entry.ClientID
	p.ClientSecret = ""
	if entry.DisplayName != "" {
		p.DisplayName = entry.DisplayName
	}
	login := "https://login.microsoftonline.com/" + url.PathEscape(entry.Tenant) + "/oauth2/v2.0/"
	p.AuthURL, p.TokenURL = login+"authorize", login+"token"
	p.Credential = s.credentialFor(entry, p.TokenURL)
	p.VouchesEmail = ownDirectory(entry.Tenant)
	return &p, nil
}

// ownDirectory says a registration is limited to one named tenant, whose
// directory is the customer's own. Microsoft's shared endpoints admit other
// tenants, whose administrators can set an address to anything.
func ownDirectory(tenant string) bool {
	switch strings.ToLower(tenant) {
	case "common", "organizations", "consumers":
		return false
	}
	return true
}

// credentialFor authenticates a token exchange. The secret is decrypted here,
// inside the exchange, and nowhere else.
func (s *Service) credentialFor(entry *Entry, tokenURL string) func(ctx context.Context, form url.Values) error {
	return func(ctx context.Context, form url.Values) error {
		if s.keys == nil {
			return ErrNoKeyService
		}
		switch entry.Credential.Kind {
		case KindCertificate:
			if entry.Credential.Certificate == nil {
				return errors.New("federation entry has no certificate")
			}
			assertion, err := s.assertion(ctx, entry.Credential.Certificate, entry.ClientID, tokenURL)
			if err != nil {
				return err
			}
			form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
			form.Set("client_assertion", assertion)
			return nil
		case KindSecret:
			secret, err := s.open(ctx, entry.Credential.WrappedSecret)
			if err != nil {
				return err
			}
			form.Set("client_secret", string(secret))
			return nil
		}
		return fmt.Errorf("unknown credential kind %q", entry.Credential.Kind)
	}
}

// assertion builds the private_key_jwt the token endpoint verifies against the
// certificate the customer uploaded, once per sign-in.
func (s *Service) assertion(ctx context.Context, cert *Certificate, clientID, tokenURL string) (string, error) {
	b64 := base64.RawURLEncoding.EncodeToString
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "x5t": cert.Thumbprint})
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := time.Now()
	body, _ := json.Marshal(map[string]any{
		"iss": clientID, "sub": clientID, "aud": tokenURL, "jti": hex.EncodeToString(jti),
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(assertionLifetime).Unix(),
	})
	input := b64(hdr) + "." + b64(body)
	digest := sha256.Sum256([]byte(input))
	sig, err := s.keys.Sign(ctx, cert.KeyRef, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign assertion: %w", err)
	}
	return input + "." + b64(sig), nil
}

// serviceSigner lets x509 sign a certificate with a key the KeyService holds.
type serviceSigner struct {
	ctx  context.Context
	keys KeyService
	ref  string
	pub  *rsa.PublicKey
}

func (k serviceSigner) Public() crypto.PublicKey { return k.pub }

func (k serviceSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("only SHA-256 signing is available")
	}
	return k.keys.Sign(k.ctx, k.ref, digest)
}

// commonName names the certificate after the registration it signs for, or
// after the sign-in client when it is prepared before the registration exists.
func commonName(clientID, upstreamClient string) string {
	if upstreamClient == "" {
		return "Federation for sign-in client " + clientID
	}
	return "Federation " + upstreamClient
}

func (s *Service) generateCertificate(ctx context.Context, clientID, provider, upstreamClient string) (*Certificate, error) {
	id := make([]byte, 6)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	tag := sha256.Sum256([]byte(clientID))
	name := fmt.Sprintf("fed-%x-%s-%x", tag[:6], provider, id)
	ref, pub, err := s.keys.CreateSigningKey(ctx, name)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{Organization: []string{"Privasys ID"}, CommonName: commonName(clientID, upstreamClient)},
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.Add(certificateLifetime),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, serviceSigner{ctx: ctx, keys: s.keys, ref: ref, pub: pub})
	if err != nil {
		s.destroy(ctx, ref)
		return nil, fmt.Errorf("certificate: %w", err)
	}
	thumb := sha1.Sum(der) //nolint:gosec // see the import.
	return &Certificate{
		KeyRef:     ref,
		PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Thumbprint: base64.RawURLEncoding.EncodeToString(thumb[:]),
		NotAfter:   tmpl.NotAfter,
	}, nil
}

// seal envelope-encrypts a secret: a fresh data key encrypts it here, and the
// KeyService wraps the data key, so the row never holds anything usable by itself.
func (s *Service) seal(ctx context.Context, secret []byte) (string, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return "", err
	}
	wrapped, err := s.keys.Wrap(ctx, dek)
	if err != nil {
		return "", fmt.Errorf("wrap: %w", err)
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	std := base64.StdEncoding.EncodeToString
	return std(wrapped) + "." + std(nonce) + "." + std(gcm.Seal(nil, nonce, secret, nil)), nil
}

func (s *Service) open(ctx context.Context, sealed string) ([]byte, error) {
	parts := strings.Split(sealed, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed wrapped secret")
	}
	var fields [3][]byte
	for i, p := range parts {
		raw, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return nil, errors.New("malformed wrapped secret")
		}
		fields[i] = raw
	}
	dek, err := s.keys.Unwrap(ctx, fields[0])
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, fields[1], fields[2], nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
