// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package recovery

import (
	"html/template"
	"net/http"
	"regexp"
)

// The page a guardian invitation email links to. An email cannot link to the
// wallet's own scheme (mail clients do not make privasys-wallet:// clickable),
// so it links here, and this page offers the wallet link, plus the stores for
// someone who does not have the wallet yet. The token is a capability: the
// page shows it to no one and logs nothing; it only goes into the wallet link.

var inviteTokenShape = regexp.MustCompile(`^[0-9a-f]{32}$`)

var invitePage = template.Must(template.New("invite").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Recovery guardian invitation</title>
<style>
  :root { --bg:#f6f8fa; --card:#ffffff; --text:#1f2937; --muted:#6b7280; --accent:#0e7a52; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0f1418; --card:#182027; --text:#e5e7eb; --muted:#9ca3af; --accent:#38e8a0; } }
  body { margin:0; background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  main { max-width:440px; margin:48px auto; padding:32px 24px; background:var(--card); border-radius:14px; }
  h1 { font-size:22px; margin:0 0 12px; }
  p { line-height:1.5; color:var(--muted); }
  a.open { display:block; text-align:center; margin:24px 0 8px; padding:14px; border-radius:12px; background:var(--accent); color:#fff; font-weight:600; text-decoration:none; }
  .stores { display:flex; gap:12px; justify-content:center; font-size:14px; }
  .stores a { color:var(--accent); }
</style>
</head>
<body>
<main>
  <h1>You are invited to be a recovery guardian</h1>
  <p>Someone you know asked you to help them get back into their Privasys account if they ever lose their phone. Open the invitation in Privasys Wallet to accept or decline it.</p>
  <a class="open" href="{{.WalletLink}}">Open in Privasys Wallet</a>
  <p>No wallet yet? Install it, then come back to this email and tap the link again.</p>
  <div class="stores">
    <a href="https://apps.apple.com/app/privasys-wallet/id6761209489">App Store</a>
    <a href="https://play.google.com/store/apps/details?id=org.privasys.wallet">Google Play</a>
  </div>
</main>
</body>
</html>
`))

// HandleGuardianInvitePage serves GET /guardians/invite?token=...
func (h *Handler) HandleGuardianInvitePage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if !inviteTokenShape.MatchString(token) {
		http.Error(w, "This invitation link is not valid.", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_ = invitePage.Execute(w, struct{ WalletLink template.URL }{
		// The token is 32 hex characters (checked above), so nothing in it
		// needs escaping inside the URL.
		WalletLink: template.URL("privasys-wallet://account-recovery?invite=" + token),
	})
}
