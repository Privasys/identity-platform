// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package spend

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Privasys/idp/internal/tokens"
)

// TokenTyp is the JOSE typ of a spend token.
const TokenTyp = "spend+jwt"

// AssertionTyp is the JOSE typ of the client assertion an app signs to
// request a token (private_key_jwt, RFC 7523 profile).
const AssertionTyp = "spend-client+jwt"

// TokenPath is the endpoint an app calls to obtain a spend token.
const TokenPath = "/spend/token"

// Authenticator resolves the user behind a bearer (an access token or a
// wallet session token). Provided by the sessions store.
type Authenticator func(r *http.Request) (userID string, err error)

// AccountEnsurer makes sure the user has a platform account the credit
// service can debit (mgmt EnsureAccount). Optional; nil skips it.
type AccountEnsurer func(ctx context.Context, sub string) error

// Handler serves the consent and token endpoints.
type Handler struct {
	store      *Store
	issuer     *tokens.Issuer
	auth       Authenticator
	keys       *keyCache
	resolver   AppResolver
	ensure     AccountEnsurer
	subjectFor SubjectFor
	sessionKey SessionKey
	outbox     *Outbox
	ttl        time.Duration
	now        func() time.Time
}

// SubjectFor derives, forward, the subject an app sees for an account: the
// account id for an app whose client shares it, the client's own subject
// otherwise. Wired from the client registry; identity when nil.
type SubjectFor func(userID, appID string) string

// SessionKey returns the public key (SEC1) of the passkey behind the
// request's wallet session, the key a spend binding must be signed by.
type SessionKey func(r *http.Request) ([]byte, error)

// Config wires a Handler.
type Config struct {
	Store    *Store
	Issuer   *tokens.Issuer
	Auth     Authenticator
	Resolver AppResolver
	Ensure   AccountEnsurer
	// SubjectFor keys consents by the subject the app sees (see SubjectFor).
	SubjectFor SubjectFor
	// SessionKey names the passkey a wallet's spend binding is signed by.
	SessionKey SessionKey
	// Outbox tells the platform which account a consent's handle debits.
	Outbox *Outbox
	// TokenTTL bounds a spend token's lifetime (default 24h). A token also
	// never outlives the consent session behind it.
	TokenTTL time.Duration
	// HTTP is the client used to fetch app JWKS (tests inject one).
	HTTP *http.Client
}

// New builds a Handler.
func New(c Config) *Handler {
	ttl := c.TokenTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	subjectFor := c.SubjectFor
	if subjectFor == nil {
		subjectFor = func(userID, _ string) string { return userID }
	}
	h := &Handler{
		store:      c.Store,
		issuer:     c.Issuer,
		auth:       c.Auth,
		keys:       newKeyCache(c.Resolver, c.HTTP),
		resolver:   c.Resolver,
		ensure:     c.Ensure,
		subjectFor: subjectFor,
		sessionKey: c.SessionKey,
		outbox:     c.Outbox,
		ttl:        ttl,
		now:        time.Now,
	}
	// A consent revoked through its session (the wallet's sessions list)
	// reports its handle dead like one withdrawn here.
	c.Store.SetRevokeNotifier(func(consent *Consent) { h.tell("revoke", consent) })
	return h
}

// tell queues the signed statement that binds (or unbinds) a consent's
// handle to its account, for every control plane the IdP serves.
func (h *Handler) tell(kind string, c *Consent) {
	if h.outbox == nil || c == nil || c.Ledger == "" {
		return
	}
	stmt, err := h.issuer.IssueLedgerHandleStatement(tokens.LedgerHandleStatement{
		Kind: kind, Handle: c.Ledger, Account: c.UserID, AppID: c.AppID, Cap: c.Cap, SID: c.SID,
		WalletSig: c.WalletSig, HolderPub: c.HolderPub, IssuedAt: h.now(), JTI: randomID(),
	})
	if err != nil {
		log.Printf("spend: ledger statement for %s: %v", c.AppID, err)
		return
	}
	if err := h.outbox.Enqueue(c.Ledger, kind, stmt); err != nil {
		log.Printf("spend: enqueue ledger %s for %s: %v", kind, c.AppID, err)
	}
}

// NotifyRevoked reports a consent revoked elsewhere (the holder removing the
// app) so the platform learns its handle is dead.
func (h *Handler) NotifyRevoked(c *Consent) { h.tell("revoke", c) }

// RegisterFilled queues a registration for every consent that got its
// handle in a startup fill (FillSubjects): the platform learns them once.
func (h *Handler) RegisterFilled(consents []*Consent) {
	for _, c := range consents {
		h.tell("register", c)
	}
}

// verifyWalletBinding checks the holder's own signature over
// handle‖0‖app_id‖0‖cap, raw P-256, by pub: the passkey of the identity
// that consents, which the IdP looked up itself from the wallet session.
// Each identity has its own passkey, so the key links nothing.
func verifyWalletBinding(handle, appID string, cap int64, sigB64 string, pub []byte) error {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return errors.New("wallet_sig must be 64 raw bytes, base64url")
	}
	if len(pub) != 65 || pub[0] != 0x04 {
		return errors.New("the passkey is not a SEC1 uncompressed P-256 point")
	}
	x, y := new(big.Int).SetBytes(pub[1:33]), new(big.Int).SetBytes(pub[33:])
	if !elliptic.P256().IsOnCurve(x, y) {
		return errors.New("holder_pub is not on P-256")
	}
	msg := []byte(handle + "\x00" + BindingAppID(appID) + "\x00" + strconv.FormatInt(cap, 10))
	d := sha256.Sum256(msg)
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !ecdsa.Verify(key, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return errors.New("wallet_sig does not verify over handle, app and cap")
	}
	return nil
}

// --- consents (user-facing) --------------------------------------------

// HandleListConsents serves GET /spend/consents: the user's live spenders.
func (h *Handler) HandleListConsents(w http.ResponseWriter, r *http.Request) {
	userID, err := h.auth(r)
	if err != nil {
		httpUnauth(w, err.Error())
		return
	}
	list, err := h.store.List(userID)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []*Consent{}
	}
	// A consent granted before its app could be named (recorded by the
	// wallet with the id alone, or while the app was not yet deployed) is
	// named now, so the account page never shows a raw id. Best effort.
	for _, c := range list {
		if (c.AppName != "" && c.AppHost != "") || h.resolver == nil {
			continue
		}
		if _, name, host, err := h.resolver.JWKSURL(r.Context(), c.AppID); err == nil {
			if c.AppName == "" {
				c.AppName = name
			}
			if c.AppHost == "" {
				c.AppHost = host
			}
			_ = h.store.SetDisplay(userID, c.AppID, c.AppHost, c.AppName)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"consents": list})
}

// HandleGetConsent serves GET /spend/consents/{app_id}.
func (h *Handler) HandleGetConsent(w http.ResponseWriter, r *http.Request) {
	userID, err := h.auth(r)
	if err != nil {
		httpUnauth(w, err.Error())
		return
	}
	appID := NormaliseAppID(r.PathValue("app_id"))
	c, err := h.store.Get(userID, appID)
	if errors.Is(err, ErrNotFound) {
		httpErr(w, http.StatusNotFound, "no consent for this app")
		return
	}
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// HandleGrantConsent serves POST /spend/consents:
//
//	{"app_id": "<hex app id | client id>", "cap": <credits/month>,
//	 "app_host": "...", "app_name": "..."}
//
// The wallet calls it at sign-in once the user approved "this app may
// spend"; privasys.id/account calls it from the spenders list. It also
// makes sure the user has a platform account, so a wallet-only user
// becomes billable the moment they consent.
func (h *Handler) HandleGrantConsent(w http.ResponseWriter, r *http.Request) {
	userID, err := h.auth(r)
	if err != nil {
		httpUnauth(w, err.Error())
		return
	}
	var req struct {
		AppID   string `json:"app_id"`
		AppHost string `json:"app_host"`
		AppName string `json:"app_name"`
		Cap     int64  `json:"cap"`
		// The wallet mints the ledger handle and signs handle‖app‖cap with
		// the identity's passkey; a wallet that predates handles sends none.
		LedgerHandle string `json:"ledger_handle"`
		WalletSig    string `json:"wallet_sig"`
		// HolderPub was the phone-wide holder key of wallets 1.4.34 and
		// 1.4.35 (TestFlight only). It linked an phone's identities, so it
		// is refused: the passkey is looked up here instead.
		HolderPub string `json:"holder_pub"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	appID := NormaliseAppID(req.AppID)
	if appID == "" {
		httpErr(w, http.StatusBadRequest, "app_id required")
		return
	}
	if req.Cap < 0 {
		httpErr(w, http.StatusBadRequest, "cap must not be negative")
		return
	}
	if req.LedgerHandle != "" && !ValidHandle(req.LedgerHandle) {
		httpErr(w, http.StatusBadRequest, "ledger_handle must be 16 bytes base64url")
		return
	}
	if req.HolderPub != "" {
		httpErr(w, http.StatusBadRequest, "holder_pub is not accepted: the binding is signed with the identity's passkey (update the wallet)")
		return
	}
	if req.LedgerHandle == "" && req.WalletSig != "" {
		httpErr(w, http.StatusBadRequest, "a wallet signature needs the handle it signs")
		return
	}
	var holderPub string
	if req.WalletSig != "" {
		if h.sessionKey == nil {
			httpErr(w, http.StatusInternalServerError, "spend: passkey lookup not wired")
			return
		}
		pub, err := h.sessionKey(r)
		if err != nil {
			httpErr(w, http.StatusBadRequest, "a signed binding needs a wallet session: "+err.Error())
			return
		}
		if err := verifyWalletBinding(req.LedgerHandle, appID, req.Cap, req.WalletSig, pub); err != nil {
			httpErr(w, http.StatusBadRequest, err.Error())
			return
		}
		holderPub = base64.RawURLEncoding.EncodeToString(pub)
	}
	// Fill the display fields from the platform when the caller did not:
	// the consent row is what the user sees under "Apps that may spend".
	if (req.AppHost == "" || req.AppName == "") && h.resolver != nil {
		if _, name, host, err := h.resolver.JWKSURL(r.Context(), appID); err == nil {
			if req.AppHost == "" {
				req.AppHost = host
			}
			if req.AppName == "" {
				req.AppName = name
			}
		} else if errors.Is(err, ErrUnknownApp) {
			httpErr(w, http.StatusNotFound, "unknown app")
			return
		}
	}
	c, err := h.store.Grant(userID, h.subjectFor(userID, appID), appID,
		strings.ToLower(strings.TrimSpace(req.AppHost)), strings.TrimSpace(req.AppName), req.Cap,
		HandleProof{Handle: req.LedgerHandle, WalletSig: req.WalletSig, HolderPub: holderPub})
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.tell("register", c)
	if h.ensure != nil {
		if err := h.ensure(r.Context(), userID); err != nil {
			// The consent stands; the account will also be ensured on the
			// user's first visit to privasys.id/account.
			log.Printf("spend: ensure account for consent to %s: %v", appID, err)
		}
	}
	writeJSON(w, http.StatusOK, c)
}

// HandleRevokeConsent serves DELETE /spend/consents/{app_id}.
func (h *Handler) HandleRevokeConsent(w http.ResponseWriter, r *http.Request) {
	userID, err := h.auth(r)
	if err != nil {
		httpUnauth(w, err.Error())
		return
	}
	appID := NormaliseAppID(r.PathValue("app_id"))
	c, err := h.store.Get(userID, appID)
	if err == nil {
		err = h.store.Revoke(userID, appID)
	}
	if errors.Is(err, ErrNotFound) {
		httpErr(w, http.StatusNotFound, "no consent for this app")
		return
	}
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.tell("revoke", c)
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "app_id": appID})
}

// --- token (app-facing) ------------------------------------------------

// TokenResponse is the body of a successful POST /spend/token.
type TokenResponse struct {
	SpendToken string `json:"spend_token"`
	TokenType  string `json:"token_type"`
	ExpiresIn  int64  `json:"expires_in"`
	Cap        int64  `json:"cap"`
	SID        string `json:"sid"`
}

// HandleToken serves POST /spend/token.
//
// Body (JSON or form): sub = the user the app acts for; client_assertion =
// a JWT signed by the app's spend key with iss = sub = the app id, aud =
// this endpoint's URL, a short exp and a jti. The key is looked up in the
// app's published JWKS by the assertion's kid; the app's consent from that
// user must be live. The token binds the SAME key in cnf, so only the app
// holding it can produce the per-request proofs a callee demands.
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	sub, assertion, err := readTokenRequest(r)
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	appID, key, err := h.verifyAssertion(r.Context(), assertion)
	if err != nil {
		oauthErr(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	// A consent is addressed by the subject the app names the holder by;
	// the IdP has no other way from that subject to anything. The token
	// goes back with the subject the app used and the consent's handle.
	consent, err := h.store.GetBySubject(sub, appID)
	if errors.Is(err, ErrNotFound) {
		oauthErr(w, http.StatusForbidden, "consent_required",
			"the user has not allowed this app to spend their credits, or revoked it")
		return
	}
	if err != nil {
		oauthErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	now := h.now()
	exp := now.Add(h.ttl)
	if sess, err := h.store.sessions.Get(consent.SID); err == nil && sess.ExpiresAt.Before(exp) {
		exp = sess.ExpiresAt
	}
	if !exp.After(now) {
		oauthErr(w, http.StatusForbidden, "consent_required", "the consent has expired")
		return
	}
	tok, err := h.issuer.IssueSpendToken(tokens.SpendTokenClaims{
		Subject:  sub,
		AppID:    appID,
		SID:      consent.SID,
		Ledger:   consent.Ledger,
		Cap:      consent.Cap,
		Cnf:      key.Cnf(),
		IssuedAt: now,
		Expiry:   exp,
		JTI:      randomID(),
	})
	if err != nil {
		oauthErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, TokenResponse{
		SpendToken: tok,
		TokenType:  "spend",
		ExpiresIn:  int64(exp.Sub(now).Seconds()),
		Cap:        consent.Cap,
		SID:        consent.SID,
	})
}

func readTokenRequest(r *http.Request) (sub, assertion string, err error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var req struct {
			Sub             string `json:"sub"`
			ClientAssertion string `json:"client_assertion"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
			return "", "", errors.New("invalid json")
		}
		sub, assertion = req.Sub, req.ClientAssertion
	} else {
		if err := r.ParseForm(); err != nil {
			return "", "", errors.New("invalid form")
		}
		sub, assertion = r.FormValue("sub"), r.FormValue("client_assertion")
	}
	sub = strings.TrimSpace(sub)
	assertion = strings.TrimSpace(assertion)
	if sub == "" {
		return "", "", errors.New("sub required")
	}
	if assertion == "" {
		return "", "", errors.New("client_assertion required")
	}
	return sub, assertion, nil
}

// verifyAssertion checks the app's private-key JWT and returns the app id
// and the published key that signed it.
func (h *Handler) verifyAssertion(ctx context.Context, assertion string) (string, JWK, error) {
	var key JWK
	var appID string
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithAudience(h.issuer.IssuerURL()+TokenPath),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
	)
	tok, err := parser.Parse(assertion, func(t *jwt.Token) (any, error) {
		claims, _ := t.Claims.(jwt.MapClaims)
		iss, _ := claims["iss"].(string)
		sub, _ := claims["sub"].(string)
		appID = NormaliseAppID(iss)
		if appID == "" || NormaliseAppID(sub) != appID {
			return nil, errors.New("assertion iss and sub must both be the app id")
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("assertion has no kid")
		}
		k, err := h.keys.Key(ctx, appID, kid)
		if err != nil {
			return nil, err
		}
		key = k
		return k.PublicKey()
	})
	if err != nil {
		return "", JWK{}, fmt.Errorf("client assertion: %w", err)
	}
	claims, _ := tok.Claims.(jwt.MapClaims)
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return "", JWK{}, errors.New("client assertion: exp required")
	}
	if exp.Time.Sub(h.now()) > 10*time.Minute {
		return "", JWK{}, errors.New("client assertion: exp too far ahead (max 10 minutes)")
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		return "", JWK{}, errors.New("client assertion: jti required")
	}
	return appID, key, nil
}

// --- mgmt account ensurer -------------------------------------------------

// MgmtAccountEnsurer returns an AccountEnsurer that calls the
// management-service's internal ensure endpoint with the IdP's mgmt token.
// Empty URL or token yields nil (disabled).
func MgmtAccountEnsurer(mgmtURL, token string, client *http.Client) AccountEnsurer {
	if mgmtURL == "" || token == "" {
		return nil
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	base := strings.TrimRight(mgmtURL, "/")
	return func(ctx context.Context, sub string) error {
		body, _ := json.Marshal(map[string]string{"sub": sub})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			base+"/api/v1/internal/accounts/ensure", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("ensure account: status %d", resp.StatusCode)
		}
		return nil
	}
}

// --- helpers ----------------------------------------------------------------

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("spend: rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func httpUnauth(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	httpErr(w, http.StatusUnauthorized, msg)
}

func oauthErr(w http.ResponseWriter, code int, errCode, desc string) {
	writeJSON(w, code, map[string]string{"error": errCode, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
