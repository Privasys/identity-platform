// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package oidc

import (
	"testing"

	"github.com/Privasys/idp/internal/clients"
)

func TestAttributeRequirementsForScope(t *testing.T) {
	// Client with a required_attributes whitelist: those are essential.
	cli := &clients.Client{RequiredAttributes: []string{"email", "name"}}
	req := attributeRequirementsForScope("openid email profile", cli)
	if !req["email"].Essential || !req["name"].Essential {
		t.Errorf("email/name should be essential for a whitelisted client: %+v", req)
	}
	if req["email"].Assurance != "any" {
		t.Errorf("email assurance = %q, want any", req["email"].Assurance)
	}

	// No whitelist: falls back to the email+name baseline; extras optional.
	open := attributeRequirementsForScope("openid email profile", &clients.Client{})
	if !open["email"].Essential || !open["name"].Essential {
		t.Errorf("email/name should be essential by default: %+v", open)
	}
	if open["given_name"].Essential {
		t.Errorf("given_name should be optional by default")
	}

	// identity scope → gov assurance on the KYC attributes.
	id := attributeRequirementsForScope("openid identity", &clients.Client{})
	for _, k := range []string{"birthdate", "nationality", "age_over_18", "age_over_21"} {
		if id[k].Assurance != "gov" {
			t.Errorf("%s assurance = %q, want gov", k, id[k].Assurance)
		}
		if id[k].Essential {
			t.Errorf("%s should be optional when not in the whitelist", k)
		}
	}
}
