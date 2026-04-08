// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Port          int
	ExpoPushURL   string
	SigningKey    string // EC P-256 private key PEM for JWT signing (ES256)
	IssuerURL     string // Public URL of this broker (JWT "iss")
	ASAudience    string // Attestation server audience claim
	ASRole        string // Attestation server role claim
	AppleTeamID   string // Apple Developer Team ID
	AppleBundleID string // App bundle identifier
	Production    bool   // App Store (true) vs TestFlight/dev (false)
}

func Load() *Config {
	port := 8090
	if p := os.Getenv("BROKER_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}

	expoPush := os.Getenv("EXPO_PUSH_URL")
	if expoPush == "" {
		expoPush = "https://exp.host/--/api/v2/push/send"
	}

	asAudience := os.Getenv("AS_AUDIENCE")
	if asAudience == "" {
		asAudience = "attestation-server"
	}

	asRole := os.Getenv("AS_ROLE")
	if asRole == "" {
		asRole = "attestation-server:client"
	}

	return &Config{
		Port:          port,
		ExpoPushURL:   expoPush,
		SigningKey:    os.Getenv("SIGNING_KEY"),
		IssuerURL:     os.Getenv("ISSUER_URL"),
		ASAudience:    asAudience,
		ASRole:        asRole,
		AppleTeamID:   os.Getenv("APPLE_TEAM_ID"),
		AppleBundleID: os.Getenv("APPLE_BUNDLE_ID"),
		Production:    os.Getenv("PRODUCTION") == "true",
	}
}

func (c *Config) Addr() string {
	return fmt.Sprintf(":%d", c.Port)
}
