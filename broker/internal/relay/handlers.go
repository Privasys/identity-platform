// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		// Allow connections from privasys.org subdomains and localhost
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // Mobile clients may not send Origin
		}
		return allowedOrigin(origin)
	},
}

var originPattern = regexp.MustCompile(`^https?://(localhost(:\d+)?|(.+\.)?privasys\.(org|id))$`)

func allowedOrigin(origin string) bool {
	return originPattern.MatchString(origin)
}

// sessionIDPattern validates session IDs are safe alphanumeric + hyphens.
var sessionIDPattern = regexp.MustCompile(`^[a-zA-Z0-9\-]{8,128}$`)

// HandleWebSocket upgrades an HTTP connection to WebSocket and joins the relay.
//
// Query parameters:
//   - session: the session ID (required, 8-128 chars, alphanumeric + hyphens)
//   - role: "browser" or "wallet" (required)
func HandleWebSocket(hub *Hub, w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	role := r.URL.Query().Get("role")

	if sessionID == "" || role == "" {
		http.Error(w, `{"error":"session and role query params required"}`, http.StatusBadRequest)
		return
	}

	if !sessionIDPattern.MatchString(sessionID) {
		http.Error(w, `{"error":"invalid session ID format"}`, http.StatusBadRequest)
		return
	}

	if role != RoleBrowser && role != RoleWallet {
		http.Error(w, `{"error":"role must be 'browser' or 'wallet'"}`, http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade failed: %v", err)
		return
	}

	hub.Join(sessionID, role, conn)
}

// notifyRequest is the JSON body for POST /notify.
type notifyRequest struct {
	PushToken string `json:"pushToken"`
	SessionID string `json:"sessionId"`
	RpID      string `json:"rpId"`
	AppName   string `json:"appName,omitempty"`
	Origin    string `json:"origin"`
	BrokerURL string `json:"brokerUrl"`
	Type      string `json:"type,omitempty"` // "auth-request"

	// Session-relay fields. Only set when the SDK opted into the
	// sealed-CBOR bootstrap. They MUST be forwarded to the wallet
	// in the push payload, otherwise the wallet falls back to a
	// vanilla passkey against `rpId` (typically the IdP, which has
	// no enclave measurements) and stores a bogus `teeType:'none'`
	// trust row.
	Mode    string `json:"mode,omitempty"`    // "session-relay" | "voucher-only"
	SdkPub  string `json:"sdkPub,omitempty"`  // SEC1 P-256 base64url
	AppHost string `json:"appHost,omitempty"` // attestation target host
	Nonce   string `json:"nonce,omitempty"`   // replay window nonce
	// Sid: the IdP session id (from the browser's JWT) the voucher must
	// be written to, so the wallet targets the SAME row the browser polls.
	// Only sent on the voucher-only path.
	Sid string `json:"sid,omitempty"`
	// ExtraAppHosts: additional enclave hosts to voucher in the same
	// ceremony (multi-app attestation). The SDK has always sent this on
	// the push path; the broker previously dropped it, silently degrading
	// returning-user PUSH sign-ins to a single-host voucher (QR scans
	// were unaffected).
	ExtraAppHosts []string `json:"extraAppHosts,omitempty"`
	// ClientID: the OIDC client the session belongs to. The wallet needs
	// it on the voucher-only path to locate/create the session row via
	// POST /sessions/encauth {client_id, device_id}.
	ClientID string `json:"clientId,omitempty"`
}

// HandleNotify sends a push notification to the wallet via Expo push service.
func HandleNotify(w http.ResponseWriter, r *http.Request, expoPushURL string) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedOrigin(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request body"}`, http.StatusBadRequest)
		return
	}

	var req notifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.PushToken == "" || req.SessionID == "" || req.RpID == "" {
		http.Error(w, `{"error":"pushToken, sessionId, and rpId are required"}`, http.StatusBadRequest)
		return
	}

	// Extract client IP for wallet display.
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.Header.Get("X-Real-IP")
	}
	if clientIP == "" {
		clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}

	// Distinct push `type` so wallets route (and OLD wallets IGNORE) a
	// voucher-only request instead of mis-handling it as a sign-in — the
	// mis-route crashed the connect flow on a missing appHost.
	pushType := "auth-request"
	if req.Mode == "voucher-only" {
		pushType = "voucher-request"
	}
	// Build Expo push message
	pushData := map[string]string{
		"type":      pushType,
		"sessionId": req.SessionID,
		"rpId":      req.RpID,
		"appName":   req.AppName,
		"origin":    req.Origin,
		"brokerUrl": req.BrokerURL,
		"userAgent": r.Header.Get("User-Agent"),
		"clientIP":  clientIP,
	}
	// Forward session-relay fields verbatim when present so the wallet
	// can attest the appHost and bootstrap the sealed-CBOR session
	// instead of falling back to a vanilla passkey against the IdP.
	if req.Mode != "" {
		pushData["mode"] = req.Mode
	}
	if req.SdkPub != "" {
		pushData["sdkPub"] = req.SdkPub
	}
	if req.AppHost != "" {
		pushData["appHost"] = req.AppHost
	}
	if req.Nonce != "" {
		pushData["nonce"] = req.Nonce
	}
	// Expo push `data` values must be strings; encode the host list as a
	// JSON array string. The wallet JSON-parses it back.
	if len(req.ExtraAppHosts) > 0 {
		if enc, err := json.Marshal(req.ExtraAppHosts); err == nil {
			pushData["extraAppHosts"] = string(enc)
		}
	}
	if req.ClientID != "" {
		pushData["clientId"] = req.ClientID
	}
	if req.Sid != "" {
		pushData["sid"] = req.Sid
	}
	pushMsg := map[string]interface{}{
		"to":   req.PushToken,
		"data": pushData,
	}

	displayName := req.AppName
	if displayName == "" {
		displayName = req.RpID
	}
	pushMsg["sound"] = "default"
	if req.Mode == "voucher-only" {
		// Incremental session extension: no sign-in ceremony, one
		// biometric approval to voucher an additional enclave host.
		pushMsg["title"] = "Approval request"
		pushMsg["body"] = displayName + " wants to add a secure back-end to your session"
	} else {
		pushMsg["title"] = "Sign-in request"
		pushMsg["body"] = displayName + " wants to sign you in"
	}

	pushBody, _ := json.Marshal(pushMsg)

	pushReq, err := http.NewRequest("POST", expoPushURL, bytes.NewReader(pushBody))
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	pushReq.Header.Set("Content-Type", "application/json")
	pushReq.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(pushReq)
	if err != nil {
		log.Printf("expo push failed: %v", err)
		http.Error(w, `{"error":"push delivery failed"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	if resp.StatusCode >= 400 {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"error":"push service error"}`))
		return
	}
	w.Write([]byte(`{"status":"sent"}`))
}
