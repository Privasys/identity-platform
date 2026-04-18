// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Privasys IdP — OIDC authorization server backed by FIDO2 authentication.
//
// This is the bridge between Privasys ID and the developer platform.
// Users authenticate via hardware-bound FIDO2 keys in the app, and
// the IdP issues standard OIDC tokens that Zitadel (and any other OIDC
// client) can consume.
//
// Endpoints:
//
//	GET  /.well-known/openid-configuration  — OIDC discovery
//	GET  /jwks                               — JSON Web Key Set
//	GET  /authorize                          — Authorization request (shows QR / triggers push)
//	POST /token                              — Token exchange (code → id_token + access_token)
//	GET  /userinfo                           — User profile (consented claims)
//	POST /fido2/register/begin               — Start FIDO2 registration
//	POST /fido2/register/complete            — Complete FIDO2 registration
//	POST /fido2/authenticate/begin           — Start FIDO2 authentication
//	POST /fido2/authenticate/complete        — Complete FIDO2 authentication
//	POST /clients                            — Register OIDC client (admin)
//	GET  /healthz                            — Health check
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Privasys/idp/internal/admin"
	"github.com/Privasys/idp/internal/clients"
	"github.com/Privasys/idp/internal/config"
	"github.com/Privasys/idp/internal/e2e"
	"github.com/Privasys/idp/internal/fido2"
	"github.com/Privasys/idp/internal/oidc"
	"github.com/Privasys/idp/internal/social"
	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

func main() {
	cfg := config.Load()
	log.Printf("privasys-idp starting on :%d (issuer: %s)", cfg.Port, cfg.IssuerURL)

	// Open database.
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Token issuer (ES256).
	issuer, err := tokens.NewIssuer(cfg.SigningKeyPath, cfg.IssuerURL)
	if err != nil {
		log.Fatalf("failed to create token issuer: %v", err)
	}

	// Client registry.
	clientReg := clients.NewRegistry(db)

	// FIDO2 handler.
	fido2Handler, err := fido2.NewHandler(fido2.Config{
		RPID:          cfg.RPID,
		RPDisplayName: "Privasys",
		RPOrigins:     cfg.RPOrigins,
		DB:            db,
	})
	if err != nil {
		log.Fatalf("failed to create FIDO2 handler: %v", err)
	}

	// Authorization code store.
	codeStore := oidc.NewCodeStore()

	// Session store (maps browser session → authenticated user).
	sessionStore := oidc.NewSessionStore()

	mux := http.NewServeMux()

	// OIDC discovery (OpenID Connect + RFC 8414).
	discoveryHandler := oidc.HandleDiscovery(cfg.IssuerURL)
	mux.HandleFunc("GET /.well-known/openid-configuration", discoveryHandler)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", discoveryHandler)
	mux.HandleFunc("GET /jwks", issuer.HandleJWKS)

	// Authorization endpoint.
	mux.HandleFunc("GET /authorize", oidc.HandleAuthorize(clientReg, sessionStore, cfg.IssuerURL))

	// Token endpoint.
	mux.HandleFunc("POST /token", oidc.HandleToken(clientReg, codeStore, issuer, db))

	// UserInfo endpoint.
	mux.HandleFunc("GET /userinfo", oidc.HandleUserInfo(issuer, db))

	// FIDO2 endpoints — wallet connects here for registration/authentication.
	mux.HandleFunc("POST /fido2/register/begin", fido2Handler.BeginRegistration)
	mux.HandleFunc("POST /fido2/register/complete",
		fido2Handler.CompleteRegistration(codeStore, sessionStore))
	mux.HandleFunc("POST /fido2/authenticate/begin", fido2Handler.BeginAuthentication)
	mux.HandleFunc("POST /fido2/authenticate/complete",
		fido2Handler.CompleteAuthentication(codeStore, sessionStore))

	// Session status — browser polls this to know when wallet approved.
	mux.HandleFunc("GET /session/status", oidc.HandleSessionStatus(sessionStore))

	// Session complete — frame-host calls this after relay/social auth.
	mux.HandleFunc("POST /session/complete", oidc.HandleSessionComplete(codeStore, sessionStore))

	// Social IdP federation.
	socialProviders := social.NewProviders()
	socialProviders.Register(&social.Provider{
		Name: "github", DisplayName: "GitHub",
		AuthURL:      "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
		ClientID:     cfg.GitHubClientID,
		ClientSecret: cfg.GitHubClientSecret,
		Scopes:       []string{"read:user", "user:email"},
	})
	socialProviders.Register(&social.Provider{
		Name: "google", DisplayName: "Google",
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserInfoURL:  "https://www.googleapis.com/oauth2/v3/userinfo",
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		Scopes:       []string{"openid", "email", "profile"},
	})
	socialProviders.Register(&social.Provider{
		Name: "microsoft", DisplayName: "Microsoft",
		AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
		ClientID:     cfg.MicrosoftClientID,
		ClientSecret: cfg.MicrosoftClientSecret,
		Scopes:       []string{"openid", "email", "profile"},
	})
	socialProviders.Register(&social.Provider{
		Name: "linkedin", DisplayName: "LinkedIn",
		AuthURL:      "https://www.linkedin.com/oauth/v2/authorization",
		TokenURL:     "https://www.linkedin.com/oauth/v2/accessToken",
		UserInfoURL:  "https://api.linkedin.com/v2/userinfo",
		ClientID:     cfg.LinkedInClientID,
		ClientSecret: cfg.LinkedInClientSecret,
		Scopes:       []string{"openid", "profile", "email"},
	})

	socialHandler := social.NewHandler(socialProviders, codeStore, sessionStore, cfg.IssuerURL)
	mux.HandleFunc("GET /auth/social", socialHandler.HandleRedirect)
	mux.HandleFunc("GET /auth/social/callback", socialHandler.HandleCallback)
	mux.HandleFunc("GET /auth/social/providers", socialHandler.HandleProviders)

	// Client registration (admin endpoint).
	mux.HandleFunc("POST /clients", clients.HandleRegister(clientReg, cfg.AdminToken))

	// Admin: role management.
	mux.HandleFunc("GET /admin/users", admin.HandleListUsers(db, cfg.AdminToken))
	mux.HandleFunc("POST /admin/roles", admin.HandleGrantRole(db, cfg.AdminToken))
	mux.HandleFunc("DELETE /admin/roles", admin.HandleRevokeRole(db, cfg.AdminToken))
	mux.HandleFunc("GET /admin/roles", admin.HandleListRoles(db, cfg.AdminToken))

	// Admin: service account management.
	mux.HandleFunc("POST /admin/service-accounts", admin.HandleCreateServiceAccount(db, cfg.AdminToken))

	// Health.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// E2E test token endpoint — only active when IDP_E2E_SECRET is set.
	if cfg.E2ESecret != "" {
		log.Printf("WARNING: E2E test endpoint enabled — do NOT use in production")
		mux.HandleFunc("POST /e2e/token", e2e.HandleToken(cfg.E2ESecret, issuer, db))
	}

	// Bootstrap admin user if configured.
	admin.MaybeBootstrapAdmin(db, cfg.BootstrapAdmin)

	// Periodic cleanup of expired refresh tokens.
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			db.CleanupExpiredRefreshTokens()
		}
	}()

	// CORS middleware.
	handler := corsMiddleware(mux)

	srv := &http.Server{
		Addr:         cfg.ListenAddr(),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
	log.Println("stopped")
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
