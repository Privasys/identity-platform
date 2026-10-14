// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package tokens

import (
	"path/filepath"
	"testing"
)

// Subjects are one-way: the issuer derives them and keeps nothing. A token's
// account comes from the session it names, never from the subject.
func TestSectorSubjectsAreOneWay(t *testing.T) {
	iss, err := NewIssuer(filepath.Join(t.TempDir(), "k.pem"), "https://privasys.id")
	if err != nil {
		t.Fatal(err)
	}

	if got := iss.SubjectFor("acct-1", ""); got != "acct-1" {
		t.Fatalf("shared sector: %q, want the account id", got)
	}
	a := iss.SubjectFor("acct-1", "site-a")
	if a == "acct-1" || len(a) != 43 {
		t.Fatalf("own sector subject %q", a)
	}
	if iss.SubjectFor("acct-1", "site-a") != a {
		t.Fatal("a sector's subject is not stable")
	}
	if iss.SubjectFor("acct-1", "site-b") == a {
		t.Fatal("two sectors share a subject for one person")
	}
	if iss.SubjectFor("acct-2", "site-a") == a {
		t.Fatal("two people share a subject in one sector")
	}

	// A token with the sector subject and a live session verifies to the
	// session's account, and keeps what was issued for userinfo.
	live := map[string]string{"sid-1": "acct-1"}
	iss.SetAccountResolver(func(sid string) (string, bool) { u, ok := live[sid]; return u, ok })
	tok, err := iss.IssueAccessTokenWithSID(a, "site-a", "sid-1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := iss.VerifyAccessToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "acct-1" || claims[ClaimSubjectAsIssued] != a {
		t.Fatalf("verified: %v / %v", claims["sub"], claims[ClaimSubjectAsIssued])
	}

	// The same token after its session ended names nobody.
	delete(live, "sid-1")
	if _, err := iss.VerifyAccessToken(tok); err == nil {
		t.Fatal("a token for a revoked session still verified")
	}

	// A platform-audience token with no session names its account directly;
	// a shared-sector token with neither is its own account.
	platform, _ := iss.IssueAccessTokenWithSID(a, "privasys-platform", "", nil, map[string]string{ClaimPrivasysAccount: "acct-1"})
	if c, err := iss.VerifyAccessToken(platform); err != nil || c["sub"] != "acct-1" {
		t.Fatalf("platform token: %v %v", c["sub"], err)
	}
	shared, _ := iss.IssueAccessTokenWithSID("acct-1", "privasys-platform", "", nil, nil)
	if c, err := iss.VerifyAccessToken(shared); err != nil || c["sub"] != "acct-1" {
		t.Fatalf("shared token: %v %v", c["sub"], err)
	}
}

// The statement that binds a consent's handle to an account is signed with
// the ledger-handle type, so no resource server takes it as an access token.
func TestLedgerHandleStatement(t *testing.T) {
	iss, _ := NewIssuer(filepath.Join(t.TempDir(), "k.pem"), "https://privasys.id")
	if _, err := iss.IssueLedgerHandleStatement(LedgerHandleStatement{Kind: "bind", Handle: "h", Account: "a", AppID: "x"}); err == nil {
		t.Fatal("an unknown kind was signed")
	}
	stmt, err := iss.IssueLedgerHandleStatement(LedgerHandleStatement{Kind: "register", Handle: "h1", Account: "acct-1", AppID: "0123", Cap: 5, SID: "sid-1", WalletSig: "sig", HolderPub: "pub"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.VerifyAccessToken(stmt); err == nil {
		t.Fatal("a ledger statement verified as an access token")
	}
}
