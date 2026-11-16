// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package appmessages

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ApprovalType is an app asking the holder to approve one act: a decision with
// legal or lasting effect, which the holder approves or declines in the
// wallet, now, at an assurance the app names. Unlike a form, the shape is
// fixed: a title, labelled lines, the digest of the act, and two answers the
// wallet owns. The answer is a token bound to that act (fido2.Approvals).
const ApprovalType = "approval"

// The assurance levels an app may ask for, weakest first. The names are the
// sign-in vocabulary's, so an app reads one ladder everywhere.
const (
	// AssuranceDevice: the phone's own biometric (Face ID, fingerprint),
	// required by the passkey ceremony, on the holder's Privasys ID passkey.
	AssuranceDevice = "device"
	// AssuranceGovPresence: a live selfie matched to the holder's verified
	// passport photo in the identity-verifier enclave, then the passkey.
	AssuranceGovPresence = "gov-presence"
)

// Decisions are the two answers. The wallet draws both; an app cannot add one.
var Decisions = []string{"approve", "decline"}

const (
	maxApprovalBytes = 3 << 10
	maxApprovalTitle = 120
	maxApprovalLines = 12
	minApprovalTTL   = 60
	maxApprovalTTL   = 900
)

var hexDigestShape = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Approval is what the IdP keeps of an approval: the app's reference, the
// digest of the approval string, the digest of the act, the assurance, and
// how long it waits.
type Approval struct {
	ID        string
	Digest    string
	ActDigest string
	Assurance string
	TTL       time.Duration
}

// ErrApproval wraps every reason an approval is refused.
var ErrApproval = errors.New("invalid approval")

func approvalErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrApproval, fmt.Sprintf(format, a...))
}

// ParseApprovalPayload reads an approval payload {approval: "<JSON string>"}.
func ParseApprovalPayload(payload json.RawMessage) (Approval, error) {
	var p struct {
		Approval string `json:"approval"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &p) != nil {
		return Approval{}, approvalErr("the payload is an object with an approval string")
	}
	return ValidateApproval(p.Approval)
}

// ValidateApproval checks an approval string. Its digest is over the exact
// bytes, so the app keeps the string it sent and compares.
func ValidateApproval(s string) (Approval, error) {
	if s == "" || len(s) > maxApprovalBytes || !utf8.ValidString(s) {
		return Approval{}, approvalErr("the approval is a JSON string of at most %d bytes", maxApprovalBytes)
	}
	var raw struct {
		V         int    `json:"v"`
		ID        string `json:"id"`
		Title     string `json:"title"`
		Lines     []struct{ Label, Value string }
		ActDigest string `json:"act_digest"`
		Assurance string `json:"assurance"`
		Callback  string `json:"callback"`
		TTL       int    `json:"ttl"`
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return Approval{}, approvalErr("the approval does not parse: %v", err)
	}
	if raw.V != 1 {
		return Approval{}, approvalErr("v must be 1")
	}
	if !formIDShape.MatchString(raw.ID) {
		return Approval{}, approvalErr("id must match [A-Za-z0-9_-]{1,64}")
	}
	if raw.Title == "" || checkText("title", raw.Title, maxApprovalTitle, false) != nil {
		return Approval{}, approvalErr("title is required, plain text, at most %d characters", maxApprovalTitle)
	}
	if len(raw.Lines) > maxApprovalLines {
		return Approval{}, approvalErr("at most %d lines", maxApprovalLines)
	}
	for i, l := range raw.Lines {
		if l.Label == "" || l.Value == "" {
			return Approval{}, approvalErr("line %d needs a label and a value", i)
		}
		if err := checkText("label", l.Label, maxFieldLabel, false); err != nil {
			return Approval{}, approvalErr("line %d: %v", i, err)
		}
		if err := checkText("value", l.Value, maxFieldValue, false); err != nil {
			return Approval{}, approvalErr("line %d: %v", i, err)
		}
	}
	if !hexDigestShape.MatchString(raw.ActDigest) {
		return Approval{}, approvalErr("act_digest is a lowercase hex SHA-256")
	}
	if raw.Assurance != AssuranceDevice && raw.Assurance != AssuranceGovPresence {
		return Approval{}, approvalErr("assurance is %q or %q", AssuranceDevice, AssuranceGovPresence)
	}
	if !safePath(raw.Callback) {
		return Approval{}, approvalErr("callback must be a path on the app's host")
	}
	if raw.TTL < minApprovalTTL || raw.TTL > maxApprovalTTL {
		return Approval{}, approvalErr("ttl is between %d and %d seconds", minApprovalTTL, maxApprovalTTL)
	}
	return Approval{
		ID: raw.ID, Digest: FormDigest(s), ActDigest: raw.ActDigest,
		Assurance: raw.Assurance, TTL: time.Duration(raw.TTL) * time.Second,
	}, nil
}
