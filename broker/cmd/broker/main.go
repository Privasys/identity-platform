// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Auth broker is a stateless WebSocket relay that pairs browser and wallet
// connections by session ID. It forwards messages verbatim between paired
// connections without inspecting or modifying them.
//
// It also provides a push notification trigger endpoint so the browser SDK
// can request the auth broker to wake the wallet via Expo push.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Privasys/auth-broker/internal/appattest"
	"github.com/Privasys/auth-broker/internal/config"
	"github.com/Privasys/auth-broker/internal/oauth"
	"github.com/Privasys/auth-broker/internal/relay"
	"github.com/Privasys/auth-broker/internal/tokens"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	cfg := config.Load()
	log.Printf("auth-broker starting on :%d", cfg.Port)

	hub := relay.NewHub()
	go hub.Run()

	// In-memory store for short-form QR descriptors. The SDK PUTs the
	// descriptor here keyed by sessionId; the wallet GETs it after
	// scanning the short QR and verifies SHA-256(body)[:16] against the
	// pin in the QR. TTL'd, single-write, multi-read.
	descStore := relay.NewDescriptorStore()

	mux := http.NewServeMux()

	// WebSocket relay endpoint
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		relay.HandleWebSocket(hub, w, r)
	})

	// Connect descriptor store (short-QR side channel)
	mux.HandleFunc("/connect/", descStore.HandleConnect)

	// Push notification trigger
	notifyHandler := func(w http.ResponseWriter, r *http.Request) {
		relay.HandleNotify(w, r, cfg.ExpoPushURL)
	}
	mux.HandleFunc("POST /notify", notifyHandler)
	mux.HandleFunc("OPTIONS /notify", notifyHandler)

	// App Attest token exchange (optional — only if SIGNING_KEY is set)
	if cfg.SigningKey != "" {
		issuer, err := tokens.NewIssuer(tokens.Config{
			PrivateKeyPEM: cfg.SigningKey,
			IssuerURL:     cfg.IssuerURL,
			Audience:      cfg.ASAudience,
			Role:          cfg.ASRole,
		})
		if err != nil {
			log.Fatalf("failed to create token issuer: %v", err)
		}

		attHandler := appattest.New(appattest.Config{
			Issuer:     issuer,
			TeamID:     cfg.AppleTeamID,
			BundleID:   cfg.AppleBundleID,
			Production: cfg.Production,
		})

		mux.HandleFunc("POST /app-token", attHandler.HandleAppToken)
		mux.HandleFunc("GET /app-challenge", attHandler.HandleChallenge)
		mux.HandleFunc("GET /.well-known/openid-configuration", issuer.HandleOIDCDiscovery)
		mux.HandleFunc("GET /jwks", issuer.HandleJWKS)

		log.Printf("app-token endpoints enabled (issuer: %s)", cfg.IssuerURL)
	}

	// OAuth token exchange proxy (optional — for providers requiring client_secret)
	oauthProviders := make(map[string]oauth.ProviderSecret)
	if cfg.GitHubClientID != "" && cfg.GitHubClientSecret != "" {
		oauthProviders["github"] = oauth.ProviderSecret{
			TokenEndpoint: "https://github.com/login/oauth/access_token",
			ClientID:      cfg.GitHubClientID,
			ClientSecret:  cfg.GitHubClientSecret,
		}
	}
	if cfg.LinkedInClientID != "" && cfg.LinkedInClientSecret != "" {
		oauthProviders["linkedin"] = oauth.ProviderSecret{
			TokenEndpoint: "https://www.linkedin.com/oauth/v2/accessToken",
			ClientID:      cfg.LinkedInClientID,
			ClientSecret:  cfg.LinkedInClientSecret,
		}
	}
	if len(oauthProviders) > 0 {
		oauthHandler := oauth.New(oauth.Config{Providers: oauthProviders})
		mux.HandleFunc("POST /oauth/token", oauthHandler.HandleToken)
		mux.HandleFunc("OPTIONS /oauth/token", oauthHandler.HandleToken)
		names := make([]string, 0, len(oauthProviders))
		for k := range oauthProviders {
			names = append(names, k)
		}
		log.Printf("oauth token proxy enabled for: %v", names)
	}

	// Health
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","sessions":` + hub.SessionCountJSON() + `}`))
	})

	// Metrics
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:         cfg.Addr(),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	log.Printf("auth-broker listening on %s", cfg.Addr())
	<-done
	log.Println("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hub.Shutdown()
	srv.Shutdown(ctx)
	log.Println("auth-broker stopped")
}
