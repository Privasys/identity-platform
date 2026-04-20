// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package recovery implements account recovery: email verification, recovery
// codes, guardian-based social recovery, and multi-device enrollment.
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
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"
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

// SendVerificationCode sends a 6-digit OTP to the given email address.
func (m *Mailer) SendVerificationCode(email, code string) error {
	if !m.Enabled() {
		log.Printf("[email] Graph API not configured — would send code %s to %s", code, email)
		return nil
	}

	subject := "Privasys — Email Verification Code"
	body := fmt.Sprintf(
		"Your Privasys email verification code is:\n\n    %s\n\n"+
			"This code expires in 10 minutes. If you did not request this, ignore this email.\n",
		code,
	)

	return m.send(email, subject, body)
}

// SendGuardianInvite sends a notification to a guardian about being invited.
func (m *Mailer) SendGuardianInvite(guardianEmail, userName string) error {
	if !m.Enabled() {
		log.Printf("[email] Graph API not configured — would send guardian invite to %s", guardianEmail)
		return nil
	}

	subject := "Privasys — Recovery Guardian Invitation"
	body := fmt.Sprintf(
		"%s has invited you as a recovery guardian on Privasys.\n\n"+
			"Open the Privasys Wallet app to accept or decline this invitation.\n",
		userName,
	)

	return m.send(guardianEmail, subject, body)
}

// SendRecoveryAlert notifies guardians that a recovery is in progress.
func (m *Mailer) SendRecoveryAlert(guardianEmail, userName string) error {
	if !m.Enabled() {
		log.Printf("[email] Graph API not configured — would send recovery alert to %s", guardianEmail)
		return nil
	}

	subject := "Privasys — Account Recovery Request"
	body := fmt.Sprintf(
		"%s is attempting to recover their Privasys account.\n\n"+
			"Open the Privasys Wallet app to approve or decline this recovery request.\n",
		userName,
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

// GenerateOTP returns a cryptographically random 6-digit numeric code.
func GenerateOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// GenerateRecoveryCodes returns 12 random 16-character base32 codes.
func GenerateRecoveryCodes() ([]string, error) {
	const (
		count   = 12
		length  = 16
		charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" // base32 alphabet
	)

	codes := make([]string, count)
	for i := 0; i < count; i++ {
		buf := make([]byte, length)
		for j := 0; j < length; j++ {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
			if err != nil {
				return nil, err
			}
			buf[j] = charset[n.Int64()]
		}
		// Format as XXXX-XXXX-XXXX-XXXX for readability.
		codes[i] = string(buf[:4]) + "-" + string(buf[4:8]) + "-" + string(buf[8:12]) + "-" + string(buf[12:16])
	}
	return codes, nil
}

// HashCode returns the SHA-256 hex digest of a code (stripped of dashes).
func HashCode(code string) string {
	// Remove dashes for hashing.
	clean := make([]byte, 0, len(code))
	for _, b := range []byte(code) {
		if b != '-' {
			clean = append(clean, b)
		}
	}
	h := sha256.Sum256(clean)
	return hex.EncodeToString(h[:])
}

// GenerateID returns a random hex string suitable for identifiers.
func GenerateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
