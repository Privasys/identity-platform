// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package tokens

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Only an access token is a bearer. Everything else this key signs names a
// subject or a session for some other purpose (a spend token is held by the
// app it was granted to; a receipt lives for a year) and must never act for
// the account at the IdP.
func TestOnlyAccessTokensAreBearers(t *testing.T) {
	iss, err := NewIssuer(filepath.Join(t.TempDir(), "k.pem"), "https://privasys.id")
	if err != nil {
		t.Fatal(err)
	}
	live := map[string]string{"sid-1": "acct-1"}
	iss.SetAccountResolver(func(sid string) (string, bool) { u, ok := live[sid]; return u, ok })

	jwk := map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}
	must := func(tok string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	others := map[string]string{
		"spend": must(iss.IssueSpendToken(SpendTokenClaims{
			Subject: "acct-1", AppID: "app-1", SID: "sid-1", Cap: 100, Cnf: jwk})),
		"email receipt": must(iss.IssueEmailVerification(EmailVerificationClaims{
			Subject: "acct-1", Email: "a@example.com"})),
		"disclosure": must(iss.IssueDisclosure(DisclosureClaims{
			Subject: "acct-1", AppID: "app-1"})),
		"form answer": must(iss.IssueAppFormAnswer(AppFormAnswerClaims{
			Subject: "acct-1", AppID: "app-1", FormID: "f", FormDigest: "d", Action: "ok", JTI: "j"})),
		"op approval": must(iss.IssueOpApproval(OpApprovalClaims{
			Subject: "acct-1", AppID: "app-1", ApprovalID: "a", ApprovalDigest: "d", ActDigest: "d",
			Decision: "approve", ACR: "device", AMR: []string{"webauthn"}, JTI: "j"})),
		"key-creation grant": must(iss.IssueKeyCreationGrant(KeyCreationGrant{
			Owner: "acct-1", Scope: "users/acct-1", KeyType: "Aes256GcmKey",
			Exp: time.Now().Add(time.Hour).Unix()})),
		"ledger handle": must(iss.IssueLedgerHandleStatement(LedgerHandleStatement{
			Kind: "register", Handle: "h", Account: "acct-1", AppID: "app-1"})),
		"id token": must(iss.IssueIDToken(IDTokenClaims{
			Subject: "acct-1", Audience: "app-1", AuthTime: time.Now()})),
	}
	for name, tok := range others {
		if _, err := iss.VerifyAccessToken(tok); err == nil {
			t.Errorf("%s verified as an access token", name)
		}
		if _, err := iss.VerifyPlatformAccessToken(tok); err == nil {
			t.Errorf("%s verified as a platform access token", name)
		}
	}

	// An access token issued to an app is that app's, not the account's.
	for _, aud := range []string{"app-1", "app:abc"} {
		tok := must(iss.IssueAccessTokenWithSID("pairwise", aud, "sid-1", nil, nil))
		if _, err := iss.VerifyAccessToken(tok); err != nil {
			t.Fatalf("%s access token: %v", aud, err)
		}
		if _, err := iss.VerifyPlatformAccessToken(tok); err == nil {
			t.Errorf("an access token for %q verified for the platform", aud)
		}
	}

	// A vault approval token is a platform-audience access token bound to one
	// vault operation; it is not the account's credential at the IdP.
	vaultTok := must(iss.IssueVaultApprovalToken("acct-1", PlatformAudience, "op", "n",
		time.Now().Unix(), time.Now().Add(5*time.Minute).Unix()))
	if _, err := iss.VerifyPlatformAccessToken(vaultTok); err == nil {
		t.Error("a vault approval token verified as a platform bearer")
	}

	// The platform's own token is accepted, and names the account.
	tok := must(iss.IssueAccessTokenWithSID("acct-1", PlatformAudience, "sid-1", nil, nil))
	claims, err := iss.VerifyPlatformAccessToken(tok)
	if err != nil || claims["sub"] != "acct-1" {
		t.Fatalf("platform token: %v %v", claims, err)
	}

	// An access token with no expiry is refused.
	noExp := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://privasys.id", "sub": "acct-1", "aud": PlatformAudience, "typ": "at+jwt"})
	raw, err := noExp.SignedString(iss.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.VerifyPlatformAccessToken(raw); err == nil {
		t.Error("an access token without exp verified")
	}
}

// A test environment's audience is a platform audience only once configured.
func TestExtraPlatformAudience(t *testing.T) {
	iss, err := NewIssuer(filepath.Join(t.TempDir(), "k.pem"), "https://privasys.id")
	if err != nil {
		t.Fatal(err)
	}
	iss.SetAccountResolver(func(sid string) (string, bool) { return "acct-1", sid == "sid-1" })
	tok, err := iss.IssueAccessTokenWithSID("acct-1", "privasys-platform-test", "sid-1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer SetPlatformAudiences(nil)

	SetPlatformAudiences(nil)
	if _, err := iss.VerifyPlatformAccessToken(tok); err == nil {
		t.Error("an unconfigured audience verified for the platform")
	}
	SetPlatformAudiences([]string{" privasys-platform-test ", ""})
	if !IsPlatformAudience(PlatformAudience) || !IsPlatformAudience("privasys-platform-test") {
		t.Fatalf("audiences: %v", PlatformAudiences())
	}
	if _, err := iss.VerifyPlatformAccessToken(tok); err != nil {
		t.Errorf("configured test audience refused: %v", err)
	}
}
