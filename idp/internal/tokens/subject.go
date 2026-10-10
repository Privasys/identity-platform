// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log"
)

// Per-app subjects.
//
// The IdP used to put the account id itself in "sub" for every client, and
// every site using the Auth SDK signs in under the same relying party, so all
// of them saw the same identifier for one person and could match their
// records. Now every client sees its own subject for a person:
//
//	sub = base64url( HMAC-SHA256(key, "privasys-subject/v1" ‖ 0 ‖ client_id ‖ 0 ‖ user_id) )
//
// with key = DeriveSecret("pairwise-subject"). Two clients' subjects for one
// person are unrelated to anyone without the key. Apps that need something of
// the holder's in another service get a capability the wallet mints, never a
// shared identifier.
//
// The parameter is called "sector" because a LEGACY mode remains: an empty
// sector is the account id itself, kept only for Privasys's first-party
// clients until their cross-app dependencies have moved to capabilities.
//
// The IdP keeps the reverse map (subject to account): apps hand subjects back
// (a notification, a spend token, a disclosure) and the IdP, or the platform
// through it, must find the account. The IdP already sees which clients an
// account signs in to; the change is that relying parties no longer can.

// ClaimSubjectAsIssued holds the token's original "sub" after
// VerifyAccessToken has resolved "sub" to the account.
const ClaimSubjectAsIssued = "privasys_sub_as_issued"

const subjectDomain = "privasys-subject/v1"

// SubjectStore persists the reverse map. The store package implements it.
type SubjectStore interface {
	RememberSubject(sub, userID, sector string) error
	ResolveSubject(sub string) (userID string, ok bool)
}

// SetSubjectStore wires the reverse map. Without one, every sector behaves
// as the shared one (subject = account id), which is the pre-sector state.
func (iss *Issuer) SetSubjectStore(s SubjectStore) { iss.subjects = s }

// SubjectFor returns the subject a client in `sector` sees for an account.
func (iss *Issuer) SubjectFor(userID, sector string) string {
	if sector == "" || iss.subjects == nil || userID == "" {
		return userID
	}
	mac := hmac.New(sha256.New, iss.DeriveSecret("pairwise-subject"))
	mac.Write([]byte(subjectDomain))
	mac.Write([]byte{0})
	mac.Write([]byte(sector))
	mac.Write([]byte{0})
	mac.Write([]byte(userID))
	sub := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if err := iss.subjects.RememberSubject(sub, userID, sector); err != nil {
		log.Printf("tokens: remember subject: %v", err)
	}
	return sub
}

// ResolveSubject maps a subject any client might hold back to the account it
// names. An account id (the shared sector) resolves to itself.
func (iss *Issuer) ResolveSubject(sub string) string {
	if iss.subjects == nil || sub == "" {
		return sub
	}
	if userID, ok := iss.subjects.ResolveSubject(sub); ok {
		return userID
	}
	return sub
}
