// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package fido2

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Privasys/idp/internal/appmessages"
)

const testActDigest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

const testApproval = `{"v":1,"id":"dec_1","title":"Provisionally register a dataset",` +
	`"lines":[{"label":"Register","value":"Sensor readings"}],` +
	`"act_digest":"` + testActDigest + `","assurance":"device","callback":"/approvals/answer","ttl":300}`

// sendApproval records an approval for "holder" the way the relay does.
func (g *formRig) sendApproval(approval string) string {
	a, err := appmessages.ValidateApproval(approval)
	if err != nil {
		g.t.Fatal(err)
	}
	id, err := g.msgs.Put("holder", appmessages.Message{
		Type: appmessages.ApprovalType, Kind: "request", AppID: "11111111-2222-3333-4444-555555555555",
		FormID: a.ID, FormDigest: a.Digest, Actions: appmessages.Decisions, ActDigest: a.ActDigest,
		Assurance: a.Assurance, TTL: a.TTL, PlatformHost: "app.apps.test.privasys.org", AppSub: "sub-at-app",
	})
	if err != nil || id == "" {
		g.t.Fatalf("put: %v", err)
	}
	return id
}

func TestAnApprovalIsTheHoldersVerifiedDecisionOnThatActOnly(t *testing.T) {
	g := newFormRig(t)
	id := g.sendApproval(testApproval)

	// Only approve or decline, only the holder's own.
	if code, _ := g.call(g.approvals.HandleBegin, "holder", id, map[string]string{"decision": "maybe"}); code != http.StatusBadRequest {
		t.Fatalf("unknown decision: %d", code)
	}
	if code, _ := g.call(g.approvals.HandleBegin, "someone-else", id, map[string]string{"decision": "approve"}); code != http.StatusNotFound {
		t.Fatalf("another holder's approval: %d", code)
	}

	// The begin asks for user verification.
	code, begin := g.call(g.approvals.HandleBegin, "holder", id, map[string]string{"decision": "approve"})
	if code != http.StatusOK {
		t.Fatalf("begin: %d", code)
	}
	if uv := begin["options"].(map[string]any)["publicKey"].(map[string]any)["userVerification"]; uv != "required" {
		t.Fatalf("user verification: %v", uv)
	}
	if begin["act_digest"] != testActDigest || begin["approval_digest"] != appmessages.FormDigest(testApproval) {
		t.Fatalf("begin names: %v", begin)
	}

	// A tap without the biometric does not approve.
	if code, _ := g.call(g.approvals.HandleAnswer, "holder", id, map[string]any{"decision": "approve", "assertion": g.signFlags(begin, 0x01)}); code != http.StatusUnauthorized {
		t.Fatalf("no user verification: %d", code)
	}

	// The real thing.
	_, begin = g.call(g.approvals.HandleBegin, "holder", id, map[string]string{"decision": "approve"})
	assertion := g.sign(begin)
	code, out := g.call(g.approvals.HandleAnswer, "holder", id, map[string]any{"decision": "approve", "assertion": assertion})
	if code != http.StatusOK {
		t.Fatalf("answer: %d %v", code, out)
	}
	tok, err := jwt.Parse(out["token"].(string), func(*jwt.Token) (any, error) { return g.issuer.PublicKey(), nil })
	if err != nil || tok.Header["typ"] != "op-approval+jwt" {
		t.Fatalf("token: %v %v", err, tok.Header)
	}
	c := tok.Claims.(jwt.MapClaims)
	if c["sub"] != "sub-at-app" || c["aud"] != "approval:11111111-2222-3333-4444-555555555555" ||
		c["approval_id"] != "dec_1" || c["approval_digest"] != appmessages.FormDigest(testApproval) ||
		c["act_digest"] != testActDigest || c["decision"] != "approve" || c["acr"] != "device" {
		t.Fatalf("claims: %v", c)
	}
	if amr, _ := c["amr"].([]any); len(amr) != 1 || amr[0] != "webauthn" {
		t.Fatalf("amr: %v", c["amr"])
	}
	if _, has := c["presence"]; has {
		t.Fatal("a device approval carries no presence")
	}

	// Single use.
	if code, _ := g.call(g.approvals.HandleAnswer, "holder", id, map[string]any{"decision": "approve", "assertion": assertion}); code != http.StatusBadRequest {
		t.Fatalf("replay: %d", code)
	}
	if code, _ := g.call(g.approvals.HandleBegin, "holder", id, map[string]string{"decision": "approve"}); code != http.StatusNotFound {
		t.Fatalf("begin after answer: %d", code)
	}
}

func TestADeclineIsSignedToo(t *testing.T) {
	g := newFormRig(t)
	id := g.sendApproval(testApproval)
	_, begin := g.call(g.approvals.HandleBegin, "holder", id, map[string]string{"decision": "decline"})
	// Begun as decline, answered as approve: refused.
	if code, _ := g.call(g.approvals.HandleAnswer, "holder", id, map[string]any{"decision": "approve", "assertion": g.sign(begin)}); code != http.StatusBadRequest {
		t.Fatalf("switched decision: %d", code)
	}
	_, begin = g.call(g.approvals.HandleBegin, "holder", id, map[string]string{"decision": "decline"})
	code, out := g.call(g.approvals.HandleAnswer, "holder", id, map[string]any{"decision": "decline", "assertion": g.sign(begin)})
	if code != http.StatusOK {
		t.Fatalf("decline: %d %v", code, out)
	}
	tok, _ := jwt.Parse(out["token"].(string), func(*jwt.Token) (any, error) { return g.issuer.PublicKey(), nil })
	if tok.Claims.(jwt.MapClaims)["decision"] != "decline" {
		t.Fatal("decline not in the token")
	}
}

func TestAFormAssertionDoesNotAnswerAnApproval(t *testing.T) {
	g := newFormRig(t)
	form := g.sendForm()
	approval := g.sendApproval(testApproval)
	_, beginForm := g.call(g.forms.HandleBegin, "holder", form, map[string]string{"action": "approve"})
	g.call(g.approvals.HandleBegin, "holder", approval, map[string]string{"decision": "approve"})
	if code, _ := g.call(g.approvals.HandleAnswer, "holder", approval, map[string]any{"decision": "approve", "assertion": g.sign(beginForm)}); code == http.StatusOK {
		t.Fatal("a form's assertion answered an approval")
	}
	// Nor can the form endpoints answer an approval.
	if code, _ := g.call(g.forms.HandleBegin, "holder", approval, map[string]string{"action": "approve"}); code != http.StatusNotFound {
		t.Fatalf("form begin on an approval: %d", code)
	}
}

func TestAnApprovalWaitsOnlyItsOwnTTL(t *testing.T) {
	g := newFormRig(t)
	id := g.sendApproval(testApproval)
	m, ok := g.msgs.Get("holder", id)
	if !ok {
		t.Fatal("not stored")
	}
	if left := time.Until(time.Unix(m.ExpiresAt, 0)); left > 301*time.Second || left < 290*time.Second {
		t.Fatalf("expiry: %v", left)
	}
	if m.Assurance != "device" || m.ActDigest != testActDigest {
		t.Fatalf("stored: %+v", m)
	}
	var raw map[string]any
	b, _ := json.Marshal(m)
	_ = json.Unmarshal(b, &raw)
	if _, has := raw["app_sub"]; has {
		t.Fatal("the app's subject must never reach the wallet")
	}
}

func TestTheApprovalBindingCommitsToEveryField(t *testing.T) {
	base := approvalBinding("m", "a", "i", "d", "x", "approve", "device", 1)
	for _, other := range [][32]byte{
		approvalBinding("m2", "a", "i", "d", "x", "approve", "device", 1),
		approvalBinding("m", "a2", "i", "d", "x", "approve", "device", 1),
		approvalBinding("m", "a", "i2", "d", "x", "approve", "device", 1),
		approvalBinding("m", "a", "i", "d2", "x", "approve", "device", 1),
		approvalBinding("m", "a", "i", "d", "x2", "approve", "device", 1),
		approvalBinding("m", "a", "i", "d", "x", "decline", "device", 1),
		approvalBinding("m", "a", "i", "d", "x", "approve", "gov-presence", 1),
		approvalBinding("m", "a", "i", "d", "x", "approve", "device", 2),
	} {
		if other == base {
			t.Fatal("a field change left the binding unchanged")
		}
	}
	if base == appFormBinding("m", "a", "i", "d", "approve", 1) {
		t.Fatal("an approval binding equals a form binding")
	}
}
