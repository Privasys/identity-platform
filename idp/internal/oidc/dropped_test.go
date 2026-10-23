package oidc

import (
	"slices"
	"testing"
)

// A key named on the request but kept from the wallet is reported, so the
// relying party learns it asked for something its registration does not
// allow instead of receiving a token without it.
func TestDroppedAttributes(t *testing.T) {
	got := droppedAttributes([]string{"name", "given_name_id", "", "email"}, []string{"sub", "name", "email"})
	if !slices.Equal(got, []string{"given_name_id"}) {
		t.Fatalf("dropped = %v", got)
	}
	if got := droppedAttributes([]string{"name"}, []string{"sub", "name"}); got != nil {
		t.Fatalf("nothing dropped, got %v", got)
	}
}
