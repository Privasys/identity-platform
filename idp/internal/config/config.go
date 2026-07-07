// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all IdP configuration.
type Config struct {
	Port           int
	IssuerURL      string // e.g. https://privasys.id
	RPID           string // FIDO2 relying party ID (e.g. privasys.id)
	RPOrigins      []string
	SigningKeyPath string // Path to EC P-256 private key PEM
	DBPath         string // SQLite database path
	AdminToken     string // Bearer token for admin endpoints
	BrokerURL      string // WebSocket broker URL (for push notifications)
	BootstrapAdmin string // User ID to auto-grant privasys-platform:admin on startup

	// Social IdP configuration
	GitHubClientID        string
	GitHubClientSecret    string
	GoogleClientID        string
	GoogleClientSecret    string
	MicrosoftClientID     string
	MicrosoftClientSecret string
	LinkedInClientID      string
	LinkedInClientSecret  string

	// Email verification (Microsoft Graph API).
	AzureTenantID     string
	AzureClientID     string
	AzureClientSecret string
	MailSender        string // Sender email address (default: no-reply@privasys.org)

	// Wallet Instance Attestation (WIA). The IdP, as wallet provider, attests
	// the wallet's hardware holder key and issues a short-lived WIA JWT the
	// verifier enclave requires. See attribute-billing-plan §3.
	WIASigningKeyPath  string // wallet-provider signing key PEM (distinct from the OIDC key)
	WIAAttestationMode string // "soft" (default) | "strict"
	WIATTLHours        int    // WIA lifetime in hours (24–72)
	AppleTeamID        string
	AppleBundleID      string
	AppleAppAttestRoot string // Apple App Attest Root CA (PEM or path); required for strict iOS
	AndroidPackage     string
	AndroidAttestRoot  string // Google hardware-attestation root (PEM or path); required for strict android
	AndroidAllowTEE    bool   // when false, require StrongBox (reject plain TEE)

	// Attribute marketplace: the IdP mints disclosure vouchers by calling the
	// management-service, which resolves the attribute registry and reserves
	// the RP's credits on the ledger (keeping ledger access solely in mgmt).
	MgmtURL      string // management-service base URL for the reserve endpoint
	IdpMgmtToken string // static bearer for the internal reserve endpoint
}

// ListenAddr returns the formatted listen address.
func (c *Config) ListenAddr() string {
	return fmt.Sprintf(":%d", c.Port)
}

// Load reads configuration from environment variables.
func Load() *Config {
	port := envInt("IDP_PORT", 8091)
	issuerURL := envStr("IDP_ISSUER_URL", "https://privasys.id")

	rpID := envStr("IDP_RP_ID", "privasys.id")
	rpOrigins := strings.Split(envStr("IDP_RP_ORIGINS", issuerURL), ",")

	// VAULT_TOKEN is injected by enclave-os-virtual as a runtime secret
	// (not measured into attestation). Fall back to it for admin auth.
	adminToken := envStr("IDP_ADMIN_TOKEN", "")
	if adminToken == "" {
		adminToken = envStr("VAULT_TOKEN", "")
	}

	return &Config{
		Port:           port,
		IssuerURL:      issuerURL,
		RPID:           rpID,
		RPOrigins:      rpOrigins,
		SigningKeyPath: envStr("IDP_SIGNING_KEY_FILE", "/data/signing-key.pem"),
		DBPath:         envStr("IDP_DB_PATH", "/data/idp.db"),
		AdminToken:     adminToken,
		BrokerURL:      envStr("IDP_BROKER_URL", "https://relay.privasys.org"),
		BootstrapAdmin: envStr("IDP_BOOTSTRAP_ADMIN", ""),

		GitHubClientID:        envStr("IDP_GITHUB_CLIENT_ID", ""),
		GitHubClientSecret:    envStr("IDP_GITHUB_CLIENT_SECRET", ""),
		GoogleClientID:        envStr("IDP_GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:    envStr("IDP_GOOGLE_CLIENT_SECRET", ""),
		MicrosoftClientID:     envStr("IDP_MICROSOFT_CLIENT_ID", ""),
		MicrosoftClientSecret: envStr("IDP_MICROSOFT_CLIENT_SECRET", ""),
		LinkedInClientID:      envStr("IDP_LINKEDIN_CLIENT_ID", ""),
		LinkedInClientSecret:  envStr("IDP_LINKEDIN_CLIENT_SECRET", ""),

		AzureTenantID:     envStr("IDP_AZURE_TENANT_ID", ""),
		AzureClientID:     envStr("IDP_AZURE_CLIENT_ID", ""),
		AzureClientSecret: envStr("IDP_AZURE_CLIENT_SECRET", ""),
		MailSender:        envStr("IDP_MAIL_SENDER", "no-reply@privasys.org"),

		WIASigningKeyPath:  envStr("IDP_WIA_SIGNING_KEY_FILE", "/data/wia-signing-key.pem"),
		WIAAttestationMode: envStr("IDP_WIA_ATTESTATION_MODE", "soft"),
		WIATTLHours:        envInt("IDP_WIA_TTL_HOURS", 48),
		AppleTeamID:        envStr("IDP_APPLE_TEAM_ID", ""),
		AppleBundleID:      envStr("IDP_APPLE_BUNDLE_ID", ""),
		AppleAppAttestRoot: envPEM("IDP_APPLE_APPATTEST_ROOT"),
		AndroidPackage:     envStr("IDP_ANDROID_PACKAGE", ""),
		AndroidAttestRoot:  envPEM("IDP_ANDROID_ATTEST_ROOT"),
		AndroidAllowTEE:    envStr("IDP_WIA_ANDROID_ALLOW_TEE", "true") == "true",

		MgmtURL:      envStr("IDP_MGMT_URL", ""),
		IdpMgmtToken: envStr("IDP_MGMT_TOKEN", ""),
	}
}

// envPEM reads a PEM trust root from an env var that is either an inline PEM
// block or a path to a PEM file. Empty when unset.
func envPEM(key string) string {
	v := os.Getenv(key)
	if v == "" {
		return ""
	}
	if strings.Contains(v, "-----BEGIN") {
		return v
	}
	if data, err := os.ReadFile(v); err == nil {
		return string(data)
	}
	return v
}

func envStr(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}
