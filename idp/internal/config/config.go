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

	return &Config{
		Port:           port,
		IssuerURL:      issuerURL,
		RPID:           rpID,
		RPOrigins:      rpOrigins,
		SigningKeyPath: envStr("IDP_SIGNING_KEY_FILE", "/etc/privasys/idp-signing-key.pem"),
		DBPath:         envStr("IDP_DB_PATH", "/var/lib/privasys/idp.db"),
		AdminToken:     envStr("IDP_ADMIN_TOKEN", ""),
		BrokerURL:      envStr("IDP_BROKER_URL", "https://relay.privasys.org"),
	}
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
