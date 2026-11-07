// Package federation lets a client bring its own upstream registration for an
// external identity provider: its users sign in through the customer's Entra
// app registration instead of the platform's, and remain the same people.
package federation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// ErrNoKeyService answers a credential operation on a host with no key service
// configured. A customer's credential is never kept without one.
var ErrNoKeyService = errors.New("this identity provider has no key service for federation credentials")

// KeyService holds what protects a customer's credential: signing keys, and the
// key a secret is wrapped under. Everything else in this package goes through
// it, so moving the key material changes only ResolveKeyService.
type KeyService interface {
	// CreateSigningKey generates an RSA 2048 signing key and returns a
	// reference to it with its public half. Entra's certificate credential
	// takes RSA only. name is unique to this key.
	CreateSigningKey(ctx context.Context, name string) (ref string, pub *rsa.PublicKey, err error)
	// Sign signs a SHA-256 digest with PKCS#1 v1.5.
	Sign(ctx context.Context, ref string, digest []byte) ([]byte, error)
	// DestroySigningKey removes a signing key.
	DestroySigningKey(ctx context.Context, ref string) error
	// Wrap encrypts a data key under the wrapping key.
	Wrap(ctx context.Context, plaintext []byte) ([]byte, error)
	// Unwrap reverses Wrap.
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
}

// ResolveKeyService is the one place that knows where the key material lives.
// Today that is a directory on the identity provider's own volume, beside its
// token signing key. Nil means none is configured: entries can still be read,
// and credential operations answer ErrNoKeyService.
func ResolveKeyService() KeyService {
	dir := os.Getenv("IDP_FEDERATION_KEY_DIR")
	if dir == "" {
		dir = "/data/federation"
	}
	k, err := newFileKeys(dir)
	if err != nil {
		return nil
	}
	return k
}

// fileKeys keeps each signing key and the wrapping key as a file only the
// identity provider's user can read.
type fileKeys struct{ dir string }

var keyNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)

func newFileKeys(dir string) (*fileKeys, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &fileKeys{dir: dir}, nil
}

func (k *fileKeys) path(ref string) (string, error) {
	if !keyNamePattern.MatchString(ref) {
		return "", fmt.Errorf("invalid key reference %q", ref)
	}
	return filepath.Join(k.dir, ref+".pem"), nil
}

func (k *fileKeys) CreateSigningKey(_ context.Context, name string) (string, *rsa.PublicKey, error) {
	path, err := k.path(name)
	if err != nil {
		return "", nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		return "", nil, err
	}
	return name, &key.PublicKey, nil
}

func (k *fileKeys) Sign(_ context.Context, ref string, digest []byte) ([]byte, error) {
	path, err := k.path(ref)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("key %s is not PEM", ref)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
}

func (k *fileKeys) DestroySigningKey(_ context.Context, ref string) error {
	path, err := k.path(ref)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// wrapKey reads the wrapping key, creating it on first use. A wrapped secret
// therefore needs this file as well as the clients table to be read.
func (k *fileKeys) wrapKey() ([]byte, error) {
	path := filepath.Join(k.dir, "wrap.key")
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, errors.New("wrapping key has the wrong length")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (k *fileKeys) Wrap(_ context.Context, plaintext []byte) ([]byte, error) {
	key, err := k.wrapKey()
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (k *fileKeys) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	key, err := k.wrapKey()
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < gcm.NonceSize() {
		return nil, errors.New("wrapped key is too short")
	}
	return gcm.Open(nil, wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():], nil)
}
