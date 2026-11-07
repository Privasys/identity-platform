package oidc

import (
	"path/filepath"
	"testing"

	"github.com/Privasys/idp/internal/store"
)

// A person who signed in through a federated identity has no account of
// their own at the identity provider; a refresh token must still be issued
// for them, and consumed back to the same user and client.
func TestRefreshTokenForFederatedUserWithoutAccount(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const userID = "microsoft:c568f7a7-5fdf-4fbb-b7ce-d77094432695"
	if db.UserExists(userID) {
		t.Fatal("precondition: the federated user must not exist yet")
	}
	token, err := issueRefreshToken(db, userID, "e7abe4fee0915453151a8e673eaeb6f9", "openid offline_access", "sid-1")
	if err != nil {
		t.Fatalf("issue refresh token: %v", err)
	}
	gotUser, gotClient, gotScope, err := db.ConsumeRefreshToken(hashRefreshToken(token))
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if gotUser != userID || gotClient != "e7abe4fee0915453151a8e673eaeb6f9" || gotScope != "openid offline_access" {
		t.Fatalf("consumed %q %q %q", gotUser, gotClient, gotScope)
	}
	if !db.UserExists(userID) {
		t.Fatal("the users row was not created")
	}
	// Issuing again for the same person is fine: the row is not duplicated.
	if _, err := issueRefreshToken(db, userID, "e7abe4fee0915453151a8e673eaeb6f9", "openid offline_access", "sid-2"); err != nil {
		t.Fatalf("second issue: %v", err)
	}
}
