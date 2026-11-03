package social

// Credentials are the client ids and secrets the identity provider holds
// with each external identity provider.
type Credentials struct {
	GitHubClientID, GitHubClientSecret       string
	GoogleClientID, GoogleClientSecret       string
	MicrosoftClientID, MicrosoftClientSecret string
	LinkedInClientID, LinkedInClientSecret   string
}

// DefaultProviders is the set of external identity providers this identity
// provider federates, with the endpoints it reads each one from. It lives
// here, next to the claim map that names each provider's identifier, so a
// test can hold the two together: the user-info endpoint decides which
// field carries the person's stable id (Graph's "id", an OIDC userinfo's
// "sub"), and changing one without the other would silently give returning
// people new accounts.
func DefaultProviders(c Credentials) []*Provider {
	return []*Provider{
		{
			Name: "github", DisplayName: "GitHub",
			AuthURL:      "https://github.com/login/oauth/authorize",
			TokenURL:     "https://github.com/login/oauth/access_token",
			UserInfoURL:  "https://api.github.com/user",
			ClientID:     c.GitHubClientID,
			ClientSecret: c.GitHubClientSecret,
			Scopes:       []string{"read:user", "user:email"},
			PKCE:         true,
		},
		{
			Name: "google", DisplayName: "Google",
			AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			UserInfoURL:  "https://www.googleapis.com/oauth2/v3/userinfo",
			ClientID:     c.GoogleClientID,
			ClientSecret: c.GoogleClientSecret,
			Scopes:       []string{"openid", "email", "profile"},
			PKCE:         true,
		},
		{
			// Read from Microsoft Graph, which names the person by the
			// directory object id ("id", the "oid" of Microsoft's own
			// tokens): the same identity whatever app registration they
			// signed in through. Microsoft's OIDC userinfo would say "sub",
			// a pairwise value per registration, so the endpoint and the
			// claim map's "id" go together (see DefaultProviders).
			Name: "microsoft", DisplayName: "Microsoft",
			AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
			ClientID:     c.MicrosoftClientID,
			ClientSecret: c.MicrosoftClientSecret,
			Scopes:       []string{"openid", "email", "profile"},
			PKCE:         true,
		},
		{
			Name: "linkedin", DisplayName: "LinkedIn",
			AuthURL:      "https://www.linkedin.com/oauth/v2/authorization",
			TokenURL:     "https://www.linkedin.com/oauth/v2/accessToken",
			UserInfoURL:  "https://api.linkedin.com/v2/userinfo",
			ClientID:     c.LinkedInClientID,
			ClientSecret: c.LinkedInClientSecret,
			Scopes:       []string{"openid", "profile", "email"},
			// LinkedIn is a confidential client and does not support PKCE; it
			// authenticates with the client secret only. Sending a code_verifier
			// makes LinkedIn reject the token exchange as invalid_client.
			PKCE: false,
		},
	}
}

// RegisterDefaults registers the default providers.
func RegisterDefaults(p *Providers, c Credentials) {
	for _, prov := range DefaultProviders(c) {
		p.Register(prov)
	}
}
