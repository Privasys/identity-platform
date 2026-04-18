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

	// Build Expo push message
	pushMsg := map[string]interface{}{
		"to": req.PushToken,
		"data": map[string]string{
			"type":      "auth-request",
			"sessionId": req.SessionID,
			"rpId":      req.RpID,
			"appName":   req.AppName,
			"origin":    req.Origin,
			"brokerUrl": req.BrokerURL,
			"userAgent": r.Header.Get("User-Agent"),
			"clientIP":  clientIP,
		},
	}

	displayName := req.AppName
	if displayName == "" {
		displayName = req.RpID
	}
	pushMsg["sound"] = "default"
	pushMsg["title"] = "Sign-in request"
	pushMsg["body"] = displayName + " wants to sign you in"

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
