// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package recovery implements account recovery: recovery codes,
// guardian-based social recovery, and multi-device enrollment.
package recovery

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tyler-smith/go-bip39"
)

// Mailer sends verification emails via Microsoft Graph API.
type Mailer struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	Sender       string // e.g. no-reply@privasys.org

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Enabled returns true if email sending is configured.
func (m *Mailer) Enabled() bool {
	return m.TenantID != "" && m.ClientID != "" && m.ClientSecret != ""
}

// SendGuardianInvite sends an invitation email with a deep link to become a guardian.
// userName is the inviting user's self-reported display name (from the wallet).
func (m *Mailer) SendGuardianInvite(guardianEmail, userName, inviteToken string) error {
	if !m.Enabled() {
		log.Printf("[email] Graph API not configured — would send guardian invite to %s (token: %s)", guardianEmail, inviteToken)
		return nil
	}

	deepLink := fmt.Sprintf("https://privasys.id/guardian?token=%s", inviteToken)

	// Use a fallback if the wallet didn't provide a name.
	if userName == "" {
		userName = "A Privasys user"
	}

	subject := "Privasys — Recovery Guardian Invitation"
	body := fmt.Sprintf(
		"%s has invited you as a recovery guardian on Privasys.\n\n"+
			"As a recovery guardian, you help protect their account by approving "+
			"recovery requests if they ever lose access to their device.\n\n"+
			"To accept this invitation, tap the link below:\n\n"+
			"    %s\n\n"+
			"If you already have the Privasys Wallet app installed, the link will "+
			"open directly in the app. Otherwise, you'll be directed to download it.\n\n"+
			"This invitation expires in 7 days.\n",
		userName, deepLink,
	)

	return m.send(guardianEmail, subject, body)
}

func (m *Mailer) getToken() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.token != "" && time.Now().Before(m.expires) {
		return m.token, nil
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", m.TenantID)
	data := url.Values{
		"client_id":     {m.ClientID},
		"client_secret": {m.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("token error: %s — %s", result.Error, result.Description)
	}

	m.token = result.AccessToken
	m.expires = time.Now().Add(time.Duration(result.ExpiresIn-60) * time.Second)
	return m.token, nil
}

func (m *Mailer) send(to, subject, body string) error {
	token, err := m.getToken()
	if err != nil {
		return fmt.Errorf("get Graph API token: %w", err)
	}

	payload := map[string]any{
		"message": map[string]any{
			"subject": subject,
			"body":    map[string]string{"contentType": "text", "content": body},
			"toRecipients": []map[string]any{
				{"emailAddress": map[string]string{"address": to}},
			},
		},
		"saveToSentItems": false,
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal email payload: %w", err)
	}

	sendURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/sendMail", m.Sender)
	req, err := http.NewRequest("POST", sendURL, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		log.Printf("[email] sent %q to %s", subject, to)
		return nil
	}

	respBody, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("Graph API error %d: %s", resp.StatusCode, respBody)
}

// --- Code generation utilities ---

// GenerateRecoveryPhrase returns a single BIP39 24-word mnemonic (256 bits of
// entropy + 8-bit checksum). High-entropy phrases make rate limiting and
// device attestation unnecessary on /recovery/begin.
func GenerateRecoveryPhrase() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

// NormalizePhrase lowercases and collapses whitespace for stable hashing.
func NormalizePhrase(phrase string) string {
	fields := strings.Fields(strings.ToLower(phrase))
	return strings.Join(fields, " ")
}

// HashPhrase returns the SHA-256 hex digest of the normalized phrase.
func HashPhrase(phrase string) string {
	h := sha256.Sum256([]byte(NormalizePhrase(phrase)))
	return hex.EncodeToString(h[:])
}

// GenerateID returns a random hex string suitable for identifiers.
func GenerateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
