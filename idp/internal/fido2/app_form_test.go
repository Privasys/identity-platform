// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package fido2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/Privasys/idp/internal/appmessages"
	"github.com/Privasys/idp/internal/store"
	"github.com/Privasys/idp/internal/tokens"
)

const testForm = `{"v":1,"id":"req_1","title":"Access to a shared file",` +
	`"blocks":[{"type":"attributes","values":{"name":"Ada"}}],` +
	`"actions":[{"id":"approve","kind":"approve"},{"id":"deny","kind":"deny"}],"callback":"/answer"}`

type formRig struct {
	t         *testing.T
	forms     *AppForms
	approvals *Approvals
	msgs      *appmessages.Store
	issuer    *tokens.Issuer
	key       *ecdsa.PrivateKey
	credID    []byte
}

func newFormRig(t *testing.T) *formRig {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h, err := NewHandler(Config{RPID: "privasys.id", RPDisplayName: "Privasys", RPOrigins: []string{"https://privasys.id"}, DB: db})
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := appmessages.New(db.DB)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "signing.pem")
	issuer, err := tokens.NewIssuer(keyPath, "https://privasys.id")
	if err != nil {
		t.Fatal(err)
	}

	// One holder with one passkey.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := []byte("credential-1")
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: pad32(key.X.Bytes()), -3: pad32(key.Y.Bytes())})
	if err := db.EnsureUser("holder"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO credentials (credential_id, user_id, public_key, aaguid, sign_count, attestation_type, device_tag)
		VALUES (?, 'holder', ?, '', 0, 'none', '')`, base64.RawURLEncoding.EncodeToString(credID), cose); err != nil {
		t.Fatal(err)
	}
	auth := func(w http.ResponseWriter, r *http.Request) string {
		if u := r.Header.Get("X-Test-User"); u != "" {
			return u
		}
		w.WriteHeader(http.StatusUnauthorized)
		return ""
	}
	return &formRig{t: t, forms: h.NewAppForms(msgs, issuer, auth), approvals: h.NewApprovals(msgs, issuer, auth), msgs: msgs, issuer: issuer, key: key, credID: credID}
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// sendForm records a form for "holder" the way the relay does.
func (g *formRig) sendForm() string {
	f, err := appmessages.ValidateForm(testForm)
	if err != nil {
		g.t.Fatal(err)
	}
	id, err := g.msgs.Put("holder", appmessages.Message{
		Type: appmessages.FormType, Kind: "request", AppID: "11111111-2222-3333-4444-555555555555",
		FormID: f.ID, FormDigest: f.Digest, Actions: f.Actions, PlatformHost: "app.apps.test.privasys.org", AppSub: "sub-at-app",
	})
	if err != nil || id == "" {
		g.t.Fatalf("put: %v", err)
	}
	return id
}

func (g *formRig) call(handler http.HandlerFunc, user, id string, body any) (int, map[string]any) {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/wallet/app-forms/"+id+"/x", strings.NewReader(string(b)))
	req.SetPathValue("id", id)
	req.Header.Set("X-Test-User", user)
	rec := httptest.NewRecorder()
	handler(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// sign answers a begin's options as the holder's authenticator would.
func (g *formRig) sign(begin map[string]any) json.RawMessage { return g.signFlags(begin, 0x05) }

// signFlags signs with the given authenticator flags (0x01 user present, 0x04
// user verified).
func (g *formRig) signFlags(begin map[string]any, flags byte) json.RawMessage {
	opts := begin["options"].(map[string]any)["publicKey"].(map[string]any)
	challenge := opts["challenge"].(string)
	clientData, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": "https://privasys.id"})
	rpHash := sha256.Sum256([]byte("privasys.id"))
	authData := append(append([]byte{}, rpHash[:]...), flags, 0, 0, 0, 1)
	cdHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, g.key, digest[:])
	enc := base64.RawURLEncoding.EncodeToString
	out, _ := json.Marshal(map[string]any{
		"id": enc(g.credID), "rawId": enc(g.credID), "type": "public-key",
		"response": map[string]any{
			"authenticatorData": enc(authData), "clientDataJSON": enc(clientData),
			"signature": enc(sig), "userHandle": enc([]byte("holder")),
		},
	})
	return out
}

func TestAnAnswerIsTheHoldersSignedChoiceForThatFormAndActionOnly(t *testing.T) {
	g := newFormRig(t)
	id := g.sendForm()

	// An action the form does not offer, someone else's form, a message id
	// that is not there: none can begin.
	if code, _ := g.call(g.forms.HandleBegin, "holder", id, map[string]string{"action": "delete-everything"}); code != http.StatusBadRequest {
		t.Fatalf("unoffered action: %d", code)
	}
	if code, _ := g.call(g.forms.HandleBegin, "someone-else", id, map[string]string{"action": "approve"}); code != http.StatusNotFound {
		t.Fatalf("another holder's form: %d", code)
	}

	// Answering without beginning, or with a different action than begun.
	if code, _ := g.call(g.forms.HandleAnswer, "holder", id, map[string]any{"action": "approve", "assertion": json.RawMessage(`{}`)}); code != http.StatusBadRequest {
		t.Fatalf("answer without begin: %d", code)
	}
	code, begin := g.call(g.forms.HandleBegin, "holder", id, map[string]string{"action": "deny"})
	if code != http.StatusOK {
		t.Fatalf("begin: %d", code)
	}
	if code, _ := g.call(g.forms.HandleAnswer, "holder", id, map[string]any{"action": "approve", "assertion": g.sign(begin)}); code != http.StatusBadRequest {
		t.Fatalf("signed deny, answered approve: %d", code)
	}

	// The real thing: begin approve, sign, answer.
	_, begin = g.call(g.forms.HandleBegin, "holder", id, map[string]string{"action": "approve"})
	assertion := g.sign(begin)
	code, out := g.call(g.forms.HandleAnswer, "holder", id, map[string]any{"action": "approve", "assertion": assertion})
	if code != http.StatusOK {
		t.Fatalf("answer: %d %v", code, out)
	}
	tok, err := jwt.Parse(out["answer"].(string), func(*jwt.Token) (any, error) { return g.issuer.PublicKey(), nil })
	if err != nil || tok.Header["typ"] != "app-form-answer+jwt" {
		t.Fatalf("token: %v %v", err, tok.Header)
	}
	c := tok.Claims.(jwt.MapClaims)
	if c["sub"] != "sub-at-app" || c["aud"] != "app-form:11111111-2222-3333-4444-555555555555" ||
		c["form_id"] != "req_1" || c["form_digest"] != appmessages.FormDigest(testForm) || c["action"] != "approve" {
		t.Fatalf("claims: %v", c)
	}
	if out["app_platform_host"] != "app.apps.test.privasys.org" {
		t.Fatalf("host: %v", out["app_platform_host"])
	}

	// Single use: the form is gone, a replay of the same assertion fails, and
	// so does beginning again.
	if code, _ := g.call(g.forms.HandleAnswer, "holder", id, map[string]any{"action": "approve", "assertion": assertion}); code != http.StatusBadRequest {
		t.Fatalf("replay: %d", code)
	}
	if code, _ := g.call(g.forms.HandleBegin, "holder", id, map[string]string{"action": "approve"}); code != http.StatusNotFound {
		t.Fatalf("begin after answer: %d", code)
	}
}

func TestAnAssertionForOneFormDoesNotAnswerAnother(t *testing.T) {
	g := newFormRig(t)
	a, b := g.sendForm(), g.sendForm()
	_, beginA := g.call(g.forms.HandleBegin, "holder", a, map[string]string{"action": "approve"})
	g.call(g.forms.HandleBegin, "holder", b, map[string]string{"action": "approve"})
	// Same app, reference, content and action, begun in the same second: only
	// the IdP's own id for each sent form tells them apart, and it is bound.
	if code, _ := g.call(g.forms.HandleAnswer, "holder", b, map[string]any{"action": "approve", "assertion": g.sign(beginA)}); code == http.StatusOK {
		t.Fatal("an assertion begun for one form answered another")
	}
}

func TestTheBindingCommitsToEveryField(t *testing.T) {
	base := appFormBinding("msg", "app", "form", "digest", "approve", 1)
	for _, other := range [][32]byte{
		appFormBinding("msg2", "app", "form", "digest", "approve", 1),
		appFormBinding("msg", "app2", "form", "digest", "approve", 1),
		appFormBinding("msg", "app", "form2", "digest", "approve", 1),
		appFormBinding("msg", "app", "form", "digest2", "approve", 1),
		appFormBinding("msg", "app", "form", "digest", "deny", 1),
		appFormBinding("msg", "app", "form", "digest", "approve", 2),
	} {
		if other == base {
			t.Fatal("a field change left the binding unchanged")
		}
	}
}
