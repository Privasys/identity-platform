// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * A detail is verified on the ground privasys.id uses: a proof the wallet can
 * disclose, or an identity document's certification. Never a stored flag.
 */

import { isVerified } from '../services/attribute-verified';

describe('a verified detail', () => {
    it('holds the Attribute Verifier proof', () => {
        expect(isVerified({ verifications: [{ proof: 'jws', assurance: 'provider' }] })).toBe(true);
    });

    it('or was certified from an identity document', () => {
        expect(isVerified({ verifications: [{ assurance: 'gov' }] })).toBe(true);
    });

    it("is not one a provider merely claims, nor one observed without a proof", () => {
        expect(isVerified({ verifications: [{ assurance: 'provider' }] })).toBe(false);
        expect(isVerified({ verifications: [{ proof: 'jws', assurance: 'none' }] })).toBe(false);
        expect(isVerified({})).toBe(false);
    });
});
