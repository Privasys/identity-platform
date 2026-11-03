package federation

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// cloudKMS speaks Cloud KMS's REST API with the VM's own identity from the
// metadata server, so the identity provider holds no KMS credential.
type cloudKMS struct {
	ring, wrapKey string
	api, metadata string
	http          *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func newCloudKMS(ring, wrapKey string) *cloudKMS {
	return &cloudKMS{
		ring:     ring,
		wrapKey:  ring + "/cryptoKeys/" + wrapKey,
		api:      "https://cloudkms.googleapis.com/v1/",
		metadata: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		http:     &http.Client{Timeout: 15 * time.Second},
	}
}

func (k *cloudKMS) accessToken(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && time.Now().Before(k.expiry) {
		return k.token, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, k.metadata, nil)
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := k.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("kms: host identity: %w", err)
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("kms: host identity: status %d", resp.StatusCode)
	}
	k.token = tok.AccessToken
	k.expiry = time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second - time.Minute)
	return k.token, nil
}

// errNotReady is a key version still being generated.
var errNotReady = errors.New("kms: key not ready")

func (k *cloudKMS) call(ctx context.Context, method, path string, in, out any) error {
	tok, err := k.accessToken(ctx)
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		raw, _ := json.Marshal(in)
		body = bytes.NewReader(raw)
	}
	req, _ := http.NewRequestWithContext(ctx, method, k.api+path, body)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.http.Do(req)
	if err != nil {
		return fmt.Errorf("kms: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(string(raw), "FAILED_PRECONDITION") {
		return errNotReady
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("kms: %s: status %d: %s", path, resp.StatusCode, raw)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (k *cloudKMS) CreateSigningKey(ctx context.Context, name string) (string, *rsa.PublicKey, error) {
	err := k.call(ctx, http.MethodPost, k.ring+"/cryptoKeys?cryptoKeyId="+url.QueryEscape(name), map[string]any{
		"purpose":         "ASYMMETRIC_SIGN",
		"versionTemplate": map[string]string{"algorithm": "RSA_SIGN_PKCS1_2048_SHA256", "protectionLevel": "SOFTWARE"},
	}, nil)
	if err != nil {
		return "", nil, err
	}
	ref := k.ring + "/cryptoKeys/" + name + "/cryptoKeyVersions/1"
	for i := 0; i < 30; i++ {
		var out struct {
			PEM string `json:"pem"`
		}
		err = k.call(ctx, http.MethodGet, ref+"/publicKey", nil, &out)
		if err == nil {
			block, _ := pem.Decode([]byte(out.PEM))
			if block == nil {
				return "", nil, errors.New("kms: no public key in the reply")
			}
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return "", nil, fmt.Errorf("kms: public key: %w", err)
			}
			pub, ok := parsed.(*rsa.PublicKey)
			if !ok {
				return "", nil, errors.New("kms: public key is not RSA")
			}
			return ref, pub, nil
		}
		if !errors.Is(err, errNotReady) {
			return "", nil, err
		}
		select {
		case <-ctx.Done():
			return "", nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return "", nil, errNotReady
}

func (k *cloudKMS) Sign(ctx context.Context, ref string, digest []byte) ([]byte, error) {
	var out struct {
		Signature string `json:"signature"`
	}
	err := k.call(ctx, http.MethodPost, ref+":asymmetricSign", map[string]any{
		"digest": map[string]string{"sha256": base64.StdEncoding.EncodeToString(digest)},
	}, &out)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Signature)
}

func (k *cloudKMS) DestroySigningKey(ctx context.Context, ref string) error {
	return k.call(ctx, http.MethodPost, ref+":destroy", map[string]any{}, nil)
}

func (k *cloudKMS) Wrap(ctx context.Context, plaintext []byte) ([]byte, error) {
	var out struct {
		Ciphertext string `json:"ciphertext"`
	}
	err := k.call(ctx, http.MethodPost, k.wrapKey+":encrypt", map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}, &out)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Ciphertext)
}

func (k *cloudKMS) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	err := k.call(ctx, http.MethodPost, k.wrapKey+":decrypt", map[string]string{
		"ciphertext": base64.StdEncoding.EncodeToString(wrapped),
	}, &out)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Plaintext)
}
