// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
// The derivation is ONE-WAY and the IdP keeps NO map from a subject back to
// an account. Where a flow must act on a subject an app hands back, it goes
// through a row the holder made for that app and can end (the session a
// token names by `sid`, a spend consent, a relationship row): never through
// the subject itself. A reversible subject was considered and rejected: a
// leaked key would have turned every subject ever issued into the account
// behind it.

// ClaimSubjectAsIssued holds the token's original "sub" after
// VerifyAccessToken has resolved "sub" to the account.
const ClaimSubjectAsIssued = "privasys_sub_as_issued"

// ClaimPrivasysAccount names the account on a platform-audience token, where
// the subject may be a client's own; VerifyAccessToken uses it when the token
// names no session.
const ClaimPrivasysAccount = "privasys_account"

const subjectDomain = "privasys-subject/v1"

// AccountResolver names the account behind a live session, or ok=false when
// the session is unknown, expired or revoked. The sessions store implements
// it; VerifyAccessToken resolves a token's subject to its account through it.
type AccountResolver func(sid string) (userID string, ok bool)

// SetAccountResolver wires the sessions store. Without one, a token's subject
// is taken as the account unless it carries privasys_account.
func (iss *Issuer) SetAccountResolver(f AccountResolver) { iss.accountOf = f }

// SubjectFor returns the subject a client in `sector` sees for an account.
// Pure: nothing is stored.
func (iss *Issuer) SubjectFor(userID, sector string) string {
	if sector == "" || userID == "" {
		return userID
	}
	mac := hmac.New(sha256.New, iss.DeriveSecret("pairwise-subject"))
	mac.Write([]byte(subjectDomain))
	mac.Write([]byte{0})
	mac.Write([]byte(sector))
	mac.Write([]byte{0})
	mac.Write([]byte(userID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
