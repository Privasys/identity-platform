// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"strings"
	"testing"
)

// The bug this file exists for: an unconfigured mailer used to return nil, so
// every caller believed the invitation had been sent. The IdP ran without Graph
// credentials for an unknown period and every guardian invitation in that
// window was discarded while the inviter was told it had gone, the guardian
// never heard, and no log line said otherwise.
func TestUnconfiguredMailerFailsRatherThanPretending(t *testing.T) {
	var m Mailer // no tenant, client or secret

	if m.Enabled() {
		t.Fatal("a Mailer with no credentials reported itself as enabled")
	}
	err := m.SendGuardianInvite("guardian@example.com", "Someone", "invite-token")
	if err == nil {
		t.Fatal("an unconfigured mailer reported success; callers cannot tell an invitation was discarded")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("err = %q, want it to say the mail is unconfigured", err)
	}
}

func TestEnabledNeedsAllThreeCredentials(t *testing.T) {
	cases := []struct {
		name string
		m    Mailer
		want bool
	}{
		{"nothing set", Mailer{}, false},
		{"tenant only", Mailer{TenantID: "t"}, false},
		{"missing secret", Mailer{TenantID: "t", ClientID: "c"}, false},
		{"missing client", Mailer{TenantID: "t", ClientSecret: "s"}, false},
		{"all three", Mailer{TenantID: "t", ClientID: "c", ClientSecret: "s"}, true},
	}
	for _, c := range cases {
		if got := c.m.Enabled(); got != c.want {
			t.Errorf("%s: Enabled() = %v, want %v", c.name, got, c.want)
		}
	}
}

// The invite token is a capability: whoever holds it can become a guardian on
// the account. It must not reach the logs, which is where it used to go on the
// unconfigured path.
func TestInviteTokenIsNotInTheFailureMessage(t *testing.T) {
	var m Mailer
	const token = "super-secret-invite-token"

	err := m.SendGuardianInvite("guardian@example.com", "Someone", token)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("the invite token leaked into the error: %q", err)
	}
}
