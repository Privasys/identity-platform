// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package appmessages

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const goodApproval = `{"v":1,"id":"dec_1","title":"Grant the auditor role",` +
	`"lines":[{"label":"Person","value":"A. Lovelace"}],` +
	`"act_digest":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",` +
	`"assurance":"device","callback":"/approvals/answer","ttl":300}`

func TestAGoodApprovalIsKeptByItsDigests(t *testing.T) {
	a, err := ValidateApproval(goodApproval)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "dec_1" || a.Digest != FormDigest(goodApproval) || a.Assurance != AssuranceDevice || a.TTL != 300*time.Second {
		t.Fatalf("%+v", a)
	}
	p, _ := json.Marshal(map[string]string{"approval": goodApproval})
	if _, err := ParseApprovalPayload(p); err != nil {
		t.Fatal(err)
	}
}

func TestAnApprovalOutsideTheShapeIsRefused(t *testing.T) {
	for name, s := range map[string]string{
		"unknown field":   strings.Replace(goodApproval, `"ttl":300`, `"ttl":300,"buttons":["Pay"]`, 1),
		"no title":        strings.Replace(goodApproval, `"Grant the auditor role"`, `""`, 1),
		"bidi in title":   strings.Replace(goodApproval, `Grant the`, "Grant‮the", 1),
		"short digest":    strings.Replace(goodApproval, `9f86d081`, ``, 1),
		"upper digest":    strings.Replace(goodApproval, `9f86d081`, `9F86D081`, 1),
		"other assurance": strings.Replace(goodApproval, `"device"`, `"sms"`, 1),
		"absolute url":    strings.Replace(goodApproval, `"/approvals/answer"`, `"https://evil.example/x"`, 1),
		"host-relative":   strings.Replace(goodApproval, `"/approvals/answer"`, `"//evil.example/x"`, 1),
		"ttl too short":   strings.Replace(goodApproval, `"ttl":300`, `"ttl":10`, 1),
		"ttl too long":    strings.Replace(goodApproval, `"ttl":300`, `"ttl":86400`, 1),
		"line no value":   strings.Replace(goodApproval, `"value":"A. Lovelace"`, `"value":""`, 1),
		"bad id":          strings.Replace(goodApproval, `"dec_1"`, `"dec 1"`, 1),
		"v2":              strings.Replace(goodApproval, `"v":1`, `"v":2`, 1),
	} {
		if _, err := ValidateApproval(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
