package federation

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/Privasys/idp/internal/social"
)

func TestFileKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "federation")
	k, err := newFileKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	ref, pub, err := k.CreateSigningKey(ctx, "fed-abc-microsoft-1")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, ref+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("key file mode %o", perm)
	}
	digest := sha256.Sum256([]byte("payload"))
	sig, err := k.Sign(ctx, ref, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if err := k.DestroySigningKey(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Sign(ctx, ref, digest[:]); err == nil {
		t.Fatal("a destroyed key must not sign")
	}
	for _, bad := range []string{"../escape", "a/b", ""} {
		if _, err := k.Sign(ctx, bad, digest[:]); err == nil {
			t.Errorf("reference %q must be refused", bad)
		}
	}

	wrapped, err := k.Wrap(ctx, []byte("data key"))
	if err != nil {
		t.Fatal(err)
	}
	// A second instance reads the same wrapping key, as after a restart.
	again, _ := newFileKeys(dir)
	got, err := again.Unwrap(ctx, wrapped)
	if err != nil || string(got) != "data key" {
		t.Fatalf("unwrap: %q %v", got, err)
	}
	wrapped[len(wrapped)-1] ^= 1
	if _, err := again.Unwrap(ctx, wrapped); err == nil {
		t.Fatal("a tampered value must not open")
	}
}

// The whole path on real files: certificate, assertion, rotation, secret.
func TestServiceOnFileKeys(t *testing.T) {
	k, err := newFileKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := NewService(memStore{}, k)
	v, err := s.Set(ctx, "c1", "microsoft", certRequest())
	if err != nil {
		t.Fatal(err)
	}
	parseCert(t, v.Certificate)
	p, err := s.ProviderFor("c1", "microsoft", &social.Provider{Name: "microsoft"})
	if err != nil || p == nil {
		t.Fatalf("provider: %v %v", p, err)
	}
	form := url.Values{}
	if err := p.Credential(ctx, form); err != nil {
		t.Fatal(err)
	}
	if len(form["client_assertion"]) != 1 {
		t.Fatalf("form: %v", form)
	}

	req := certRequest()
	req.Credential.Kind, req.Credential.Secret = KindSecret, "s3cret"
	if _, err := s.Set(ctx, "c1", "microsoft", req); err != nil {
		t.Fatal(err)
	}
	p, _ = s.ProviderFor("c1", "microsoft", &social.Provider{Name: "microsoft"})
	form = url.Values{}
	if err := p.Credential(ctx, form); err != nil {
		t.Fatal(err)
	}
	if form["client_secret"][0] != "s3cret" {
		t.Fatalf("form: %v", form)
	}
}
