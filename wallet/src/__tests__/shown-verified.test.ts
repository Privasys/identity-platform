// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The wallet says an email is verified only on the ground privasys.id uses for
 * `email_verified`: a proof the wallet can disclose to the app.
 */

import { shownVerified } from '../services/shown-verified';

describe('an email shown as verified', () => {
    it('holds the Attribute Verifier proof', () => {
        expect(
            shownVerified({ key: 'email', verified: true, verifications: [{ proof: 'jws', assurance: 'provider' }] }),
        ).toBe(true);
    });

    it("is not verified on a provider's bare claim, whatever the stored flag says", () => {
        expect(shownVerified({ key: 'email', verified: true, verifications: [{ assurance: 'provider' }] })).toBe(false);
        expect(shownVerified({ key: 'email', verified: true })).toBe(false);
    });

    it('other details keep their own rule for now', () => {
        expect(shownVerified({ key: 'given_name', verified: true })).toBe(true);
        expect(shownVerified({ key: 'given_name', verified: false })).toBe(false);
    });
});
