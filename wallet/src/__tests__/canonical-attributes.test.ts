// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The wallet bundles its own copy of the canonical referential because EAS
 * builds see only the wallet directory (see the note in services/attributes.ts),
 * so `yarn sync-shared` is a manual step somebody has to remember. The IdP's
 * copy of the same file went eleven attributes stale exactly this way. These
 * tests make forgetting it a red build rather than a wallet that requests
 * attributes the IdP does not know.
 */

import { readFileSync } from 'fs';
import { join } from 'path';

import { ATTRIBUTE_MAP, CANONICAL_ATTRIBUTES, CANONICAL_KEYS } from '@/services/attributes';

const BUNDLED = join(__dirname, '..', 'shared', 'canonical-attributes.json');
const SOURCE = join(__dirname, '..', '..', '..', 'shared', 'canonical-attributes.json');

describe('canonical attribute referential', () => {
    it('bundles the shared file byte for byte', () => {
        const bundled = readFileSync(BUNDLED, 'utf8');
        const source = readFileSync(SOURCE, 'utf8');
        if (bundled !== source) {
            throw new Error(
                'wallet/src/shared/canonical-attributes.json is stale. Run `yarn sync-shared` and commit the result.'
            );
        }
    });

    it('carries the marketplace key for every paid attribute', () => {
        // The namespaced spelling is what a voucher and a billing grant must
        // agree on; reconstructing it as `privasys:${key}` would also namespace
        // the document fields the marketplace does not price.
        const paid = CANONICAL_ATTRIBUTES.filter((a) => a.marketplace);
        expect(paid.map((a) => a.key).sort()).toEqual([
            'age_over_18',
            'age_over_21',
            'birthdate',
            'family_name',
            'given_name',
            'nationality',
        ]);
        for (const a of paid) {
            expect(a.marketplace!.key).toBe(`privasys:${a.key}`);
            expect(a.marketplace!.billable).toBe(true);
            expect(a.marketplace!.assurance).toBe('gov_verified');
        }
    });

    it('leaves the unpriced document fields without a marketplace entry', () => {
        // These come off the chip alongside a priced insight. Naming one in a
        // reservation fails the whole authorization as an unknown attribute.
        for (const key of ['document_number', 'issuing_state', 'picture_id', 'sex']) {
            expect(CANONICAL_KEYS.has(key)).toBe(true);
            expect(ATTRIBUTE_MAP[key].scope).toBe('identity');
            expect(ATTRIBUTE_MAP[key].marketplace).toBeUndefined();
        }
    });

    it('knows every document attribute the chip read writes', () => {
        // services/kyc.ts stores these keys after a successful DG1 parse; the
        // IdP rejects an OAuth client that requires a key it has never heard of.
        for (const key of [
            'document_number',
            'document_type',
            'sex',
            'issuing_state',
            'doc_expiry',
            'place_of_birth',
            'personal_number',
            'given_name_id',
            'family_name_id',
            'picture_id',
        ]) {
            expect(CANONICAL_KEYS.has(key)).toBe(true);
        }
    });
});
