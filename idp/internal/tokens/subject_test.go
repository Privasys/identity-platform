// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package tokens

import (
	"path/filepath"
	"testing"
)

type memSubjects map[string]string

func (m memSubjects) RememberSubject(sub, userID, _ string) error { m[sub] = userID; return nil }
func (m memSubjects) ResolveSubject(sub string) (string, bool) {
	u, ok := m[sub]
	return u, ok
}

func TestSectorSubjects(t *testing.T) {
	iss, err := NewIssuer(filepath.Join(t.TempDir(), "k.pem"), "https://privasys.id")
	if err != nil {
		t.Fatal(err)
	}
	m := memSubjects{}
	iss.SetSubjectStore(m)

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
	if iss.ResolveSubject(a) != "acct-1" || iss.ResolveSubject("acct-1") != "acct-1" {
		t.Fatal("resolution failed")
	}

	// A token carrying the sector subject verifies to the account.
	tok, err := iss.IssueAccessTokenWithSID(a, "privasys-platform", "", nil, nil)
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

	// Without a store every sector behaves as the shared one.
	bare, _ := NewIssuer(filepath.Join(t.TempDir(), "k2.pem"), "https://privasys.id")
	if bare.SubjectFor("acct-1", "site-a") != "acct-1" {
		t.Fatal("an issuer with no subject store invented a subject")
	}
}
