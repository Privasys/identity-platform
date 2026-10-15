// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package fido2

import (
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// An identity's passkeys at privasys.id are the keys its wallet signs with:
// a sealed-session voucher and a spend binding are each signed by the
// passkey of the identity they speak for. Each identity has its own passkey
// on each phone, so nothing here links one identity to another.

// coseP256 is the COSE curve identifier of P-256.
const coseP256 = 1

// SEC1Of returns a COSE EC2 P-256 credential key as an uncompressed SEC1
// point (0x04 ‖ X ‖ Y), the form the wallet's signatures are checked against.
func SEC1Of(cose []byte) ([]byte, error) {
	k, err := webauthncose.ParsePublicKey(cose)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(webauthncose.EC2PublicKeyData)
	if !ok || ec.Curve != coseP256 || len(ec.XCoord) == 0 || len(ec.XCoord) > 32 || len(ec.YCoord) == 0 || len(ec.YCoord) > 32 {
		return nil, errors.New("the passkey is not a P-256 key")
	}
	out := make([]byte, 65)
	out[0] = 0x04
	copy(out[33-len(ec.XCoord):33], ec.XCoord)
	copy(out[65-len(ec.YCoord):], ec.YCoord)
	return out, nil
}

// SessionKey returns the public key of the passkey that opened a live wallet
// session, as an uncompressed SEC1 point.
func (h *Handler) SessionKey(token string) ([]byte, error) {
	cred := h.SessionCredential(token)
	if cred == "" {
		return nil, errors.New("not a live wallet session")
	}
	var cose []byte
	if err := h.db.QueryRow("SELECT public_key FROM credentials WHERE credential_id = ?", cred).Scan(&cose); err != nil {
		return nil, fmt.Errorf("the session's passkey: %w", err)
	}
	return SEC1Of(cose)
}

// UserKeys returns the public keys of every passkey an identity holds at
// privasys.id, one per phone, as uncompressed SEC1 points. A key that cannot
// be read is left out: it cannot have signed anything this identity sent.
func (h *Handler) UserKeys(userID string) ([][]byte, error) {
	rows, err := h.db.Query("SELECT public_key FROM credentials WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys [][]byte
	for rows.Next() {
		var cose []byte
		if err := rows.Scan(&cose); err != nil {
			return nil, err
		}
		if k, err := SEC1Of(cose); err == nil {
			keys = append(keys, k)
		}
	}
	return keys, rows.Err()
}
