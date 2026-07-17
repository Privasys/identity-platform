package admin

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/Privasys/idp/internal/store"
)

// App-initiated wallet notifications. The management-service forwards a
// confidential app's request to notify one of its users; this endpoint
// resolves the user's push target and delivers an Expo push. The
// plaintext title/body NEVER carry user content (they transit Apple/
// Google/Expo); the payload travels as a sealed envelope to the
// wallet's registered X25519 key. A user without a sealing key gets the
// generic push with no payload — the wallet registers the key on its
// next start and later notifications carry data again.

// notifySealInfo domain-separates the HKDF derivation.
const notifySealInfo = "privasys-notify-v1"

// sealToWallet encrypts payload to the wallet's X25519 public key:
// base64url( eph_pub(32) || nonce(24) || XChaCha20-Poly1305(payload) ),
// key = HKDF-SHA256(X25519(eph, wallet_pub), info=notifySealInfo),
// AAD = the notification type. The wallet mirrors this exactly.
func sealToWallet(encPubB64, typ string, payload []byte) (string, error) {
	pubRaw, err := base64.RawURLEncoding.DecodeString(encPubB64)
	if err != nil || len(pubRaw) != 32 {
		return "", errInvalidKey
	}
	curve := ecdh.X25519()
	walletPub, err := curve.NewPublicKey(pubRaw)
	if err != nil {
		return "", err
	}
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := ephPriv.ECDH(walletPub)
	if err != nil {
		return "", err
	}
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, []byte(notifySealInfo)), key); err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nil, nonce, payload, []byte(typ))
	out := make([]byte, 0, 32+len(nonce)+len(ct))
	out = append(out, ephPriv.PublicKey().Bytes()...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

var errInvalidKey = errors.New("wallet sealing key must be base64url of 32 raw bytes")

// notifyTitleBody maps a notification type to the generic, PII-free
// text shown by the OS. appName is the platform-verified display name
// of the attested app that sent the notification.
func notifyTitleBody(typ, appName string) (string, string) {
	if appName == "" {
		appName = "A confidential app"
	}
	switch typ {
	case "share-request":
		return appName, "Someone requested access to something you shared."
	case "share-decision":
		return appName, "There is an update on your access request."
	default:
		return appName, "You have a new notification."
	}
}

// HandleNotify handles POST /admin/notify (static admin token; called
// by the management-service on behalf of an attested app).
//
//	Request:  {"sub","type","payload":{...},"app_id","app_name"}
//	Response: 200 {"status":"sent"|"sent-unsealed"} | 404 no push target
func HandleNotify(db *store.DB, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkAdmin(w, r, adminToken) {
			return
		}
		var req struct {
			Sub     string          `json:"sub"`
			Type    string          `json:"type"`
			Payload json.RawMessage `json:"payload"`
			AppID   string          `json:"app_id"`
			AppName string          `json:"app_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Sub == "" || req.Type == "" {
			writeError(w, http.StatusBadRequest, "sub and type are required")
			return
		}
		token, encPub := db.GetPushTarget(req.Sub)
		if token == "" {
			writeError(w, http.StatusNotFound, "no push target for user")
			return
		}

		data := map[string]string{"type": req.Type, "app_id": req.AppID}
		status := "sent-unsealed"
		if encPub != "" && len(req.Payload) > 0 {
			sealed, err := sealToWallet(encPub, req.Type, req.Payload)
			if err != nil {
				log.Printf("admin/notify: seal failed for %s: %v", req.Type, err)
				writeError(w, http.StatusInternalServerError, "seal failed")
				return
			}
			data["sealed"] = sealed
			status = "sent"
		}

		title, body := notifyTitleBody(req.Type, req.AppName)
		if err := sendExpoPush(token, title, body, data); err != nil {
			log.Printf("admin/notify: push send failed: %v", err)
			writeError(w, http.StatusBadGateway, "push delivery failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": status})
	}
}

// sendExpoPush delivers one Expo push message. Data values must be
// strings (Expo constraint).
func sendExpoPush(pushToken, title, body string, data map[string]string) error {
	msg := []map[string]interface{}{{
		"to":    pushToken,
		"sound": "default",
		"title": title,
		"body":  body,
		"data":  data,
	}}
	payload, _ := json.Marshal(msg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://exp.host/--/api/v2/push/send", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
