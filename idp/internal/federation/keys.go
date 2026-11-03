// Package federation lets a client bring its own upstream registration for an
// external identity provider: its users sign in through the customer's Entra
// app registration instead of the platform's, and remain the same people.
package federation

import (
	"context"
	"crypto/rsa"
	"errors"
	"os"
)

// ErrNoKeyService answers a credential operation on a host with no key service
// configured. A customer's credential is never kept without one.
var ErrNoKeyService = errors.New("this identity provider has no key service for federation credentials")

// KeyService is the identity provider host's key management service. Signing
// keys are generated inside it and never leave it; a secret is wrapped under a
// key the host reaches with its own identity and never stores.
type KeyService interface {
	// CreateSigningKey generates an RSA 2048 signing key and returns a
	// reference to it with its public half. Entra's certificate credential
	// takes RSA only. name is unique to this key.
	CreateSigningKey(ctx context.Context, name string) (ref string, pub *rsa.PublicKey, err error)
	// Sign signs a SHA-256 digest with PKCS#1 v1.5.
	Sign(ctx context.Context, ref string, digest []byte) ([]byte, error)
	// DestroySigningKey schedules a signing key for destruction.
	DestroySigningKey(ctx context.Context, ref string) error
	// Wrap encrypts a data key under the host's wrapping key.
	Wrap(ctx context.Context, plaintext []byte) ([]byte, error)
	// Unwrap reverses Wrap.
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
}

// ResolveKeyService is the one place that knows which KMS the host has, so
// moving the identity provider to another host changes this function and
// nothing else. Nil means none is configured: federation entries can still be
// read, and credential operations answer ErrNoKeyService.
func ResolveKeyService() KeyService {
	ring := os.Getenv("IDP_KMS_KEYRING") // projects/<p>/locations/<l>/keyRings/<r>
	if ring == "" {
		return nil
	}
	wrap := os.Getenv("IDP_KMS_WRAP_KEY")
	if wrap == "" {
		wrap = "federation-wrap"
	}
	return newCloudKMS(ring, wrap)
}
