// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package voucher mints paid disclosure vouchers. At attribute-request time the
// IdP asks the management-service to resolve the requested attributes and
// reserve the relying party's credits (mgmt owns ledger access); for each
// per-provider grant returned, the IdP signs a voucher the wallet carries to
// the issuing enclave. See attribute-billing-plan §2–3.
package voucher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/idp/internal/tokens"
)

// Grant is one per-provider reservation the management-service returns.
type Grant struct {
	VoucherJTI        string   `json:"voucher_jti"`
	ProviderNamespace string   `json:"provider_namespace"`
	IssuerURL         string   `json:"issuer_url"`
	IssuingAppID      string   `json:"issuing_app_id,omitempty"`
	Claims            []string `json:"claims"`
	PriceCredits      int64    `json:"price_credits"`
	ExpiresAt         string   `json:"expires_at"`
}

// MintedVoucher is a signed voucher plus the routing/context the wallet needs
// to send it to the right issuing app.
type MintedVoucher struct {
	Token             string   `json:"token"`
	ProviderNamespace string   `json:"provider_namespace"`
	IssuerURL         string   `json:"issuer_url"`
	IssuingAppID      string   `json:"issuing_app_id,omitempty"`
	Claims            []string `json:"claims"`
}

// ErrInsufficient means the relying party could not cover the reservation
// (mgmt/ledger returned 402). The auth flow surfaces this as an RP-visible
// error, not a user-facing one.
var ErrInsufficient = fmt.Errorf("relying party has insufficient credits")

// Minter reserves credits via the management-service and signs the resulting
// vouchers with the IdP issuer key.
type Minter struct {
	issuer   *tokens.Issuer
	mgmtURL  string
	mgmtTok  string
	http     *http.Client
	voucherT time.Duration // voucher JWT lifetime (short; ~10 min)
}

// NewMinter builds a Minter. mgmtURL/mgmtTok address the internal reserve
// endpoint; both empty disables minting (Mint returns nil, nil) so the IdP runs
// without the marketplace configured.
func NewMinter(issuer *tokens.Issuer, mgmtURL, mgmtTok string) *Minter {
	return &Minter{
		issuer:   issuer,
		mgmtURL:  strings.TrimRight(mgmtURL, "/"),
		mgmtTok:  mgmtTok,
		http:     &http.Client{Timeout: 10 * time.Second},
		voucherT: 10 * time.Minute,
	}
}

// Enabled reports whether the marketplace reserve endpoint is configured.
func (m *Minter) Enabled() bool { return m.mgmtURL != "" && m.mgmtTok != "" }

// Mint reserves credits for the RP's requested attributes and signs one voucher
// per provider. rpAccountID is the RP's billing account (UUID string, from the
// billable client), rpID is the RP identifier stamped into each voucher (the
// enclave checks it against the request). reservationTTL controls how long the
// hold survives (long enough to outlive first-time capture). Returns nil when
// minting is disabled or no attributes were requested.
func (m *Minter) Mint(ctx context.Context, rpAccountID, rpID string, attributes []string, reservationTTL time.Duration) ([]MintedVoucher, error) {
	if !m.Enabled() || len(attributes) == 0 {
		return nil, nil
	}
	ttlSecs := int64(reservationTTL / time.Second)
	if ttlSecs <= 0 {
		ttlSecs = 1800
	}
	reqBody, _ := json.Marshal(map[string]any{
		"rp_account_id": rpAccountID,
		"attributes":    attributes,
		"ttl_seconds":   ttlSecs,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		m.mgmtURL+"/api/v1/internal/attribute-vouchers/reserve", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+m.mgmtTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusPaymentRequired {
		return nil, ErrInsufficient
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("reserve failed: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Grants []Grant `json:"grants"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	vouchers := make([]MintedVoucher, 0, len(out.Grants))
	for _, g := range out.Grants {
		tok, err := m.issuer.IssueVoucher(tokens.VoucherClaims{
			JTI:      g.VoucherJTI,
			RPID:     rpID,
			Provider: g.ProviderNamespace,
			Claims:   g.Claims,
			Credits:  g.PriceCredits,
			TTL:      m.voucherT,
		})
		if err != nil {
			return nil, err
		}
		vouchers = append(vouchers, MintedVoucher{
			Token: tok, ProviderNamespace: g.ProviderNamespace, IssuerURL: g.IssuerURL,
			IssuingAppID: g.IssuingAppID, Claims: g.Claims,
		})
	}
	return vouchers, nil
}
