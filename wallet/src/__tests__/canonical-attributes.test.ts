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

import {
    ATTRIBUTE_MAP, CANONICAL_ATTRIBUTES, CANONICAL_KEYS, GOV_VERIFIED, SELF_ASSERTED,
    attributeAssurance, certifiedFieldFor, disclosesAsToken, isDerived, marketplaceKeyFor
} from '@/services/attributes';

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

    it('carries the marketplace key on every paid attribute', () => {
        // The namespaced spelling is what a voucher and a billing grant must
        // agree on; reconstructing it as `privasys:${key}` would also namespace
        // the document fields the marketplace does not price, and would spell an
        // `_id` key wrong (it is sold under the field the enclave meters).
        const paid = CANONICAL_ATTRIBUTES.filter((a) => a.marketplace);
        expect(paid.map((a) => a.key).sort()).toEqual([
            'age_band',
            'age_over_18',
            'age_over_21',
            'birthdate',
            'birthdate_id',
            'document_valid',
            'family_name_id',
            'given_name_id',
            'nationality',
            'nationality_id',
        ]);
        for (const a of paid) {
            expect(attributeAssurance(a.key)).toBe(GOV_VERIFIED);
            expect(a.marketplace!.key).toBe(`privasys:${certifiedFieldFor(a.key)}`);
            expect(a.marketplace!.billable).toBe(true);
        }
    });

    it('leaves the unpriced document fields without a marketplace entry', () => {
        // These come off the chip alongside a priced insight. Naming one in a
        // reservation fails the whole authorization as an unknown attribute, so
        // an attribute the enclave certifies but the registry has not priced
        // must stay unnamed here until a migration seeds its row.
        for (const key of [
            'document_number', 'document_type', 'issuing_state', 'sex',
            'doc_expiry', 'place_of_birth', 'personal_number', 'picture_id',
        ]) {
            expect(CANONICAL_KEYS.has(key)).toBe(true);
            expect(ATTRIBUTE_MAP[key].scope).toBe('identity');
            expect(ATTRIBUTE_MAP[key].marketplace).toBeUndefined();
        }
    });

    it('keeps a self-asserted name and its government-backed twin apart', () => {
        // The correction this model exists for: a first name the holder typed
        // and a first name a passport certifies are two attributes with two
        // prices, so they are two keys. The bare key stays free forever.
        for (const key of ['given_name', 'family_name']) {
            expect(attributeAssurance(key)).toBe(SELF_ASSERTED);
            expect(ATTRIBUTE_MAP[key].scope).toBe('profile');
            expect(ATTRIBUTE_MAP[key].marketplace).toBeUndefined();

            const twin = ATTRIBUTE_MAP[key].govKey!;
            expect(twin).toBe(`${key}_id`);
            expect(attributeAssurance(twin)).toBe(GOV_VERIFIED);
            expect(ATTRIBUTE_MAP[twin].scope).toBe('identity');
            // Request-only, so a bare `identity` request is never billed for a
            // passport name it did not name.
            expect(ATTRIBUTE_MAP[twin].requestOnly).toBe(true);
            // The voucher matches on the referential's spelling, not a guess:
            // the enclave meters the certified field, not the storage key.
            expect(marketplaceKeyFor(twin)).toBe(`privasys:${key}`);
        }
    });

    it('adds a government-backed twin for the dual attributes', () => {
        // birthdate and nationality predate the convention and were minted
        // government-backed, so they stay exactly as they are for already
        // registered clients while the `_id` spelling becomes the one to name.
        for (const key of ['birthdate', 'nationality']) {
            const twin = `${key}_id`;
            expect(ATTRIBUTE_MAP[key].supersededBy).toBe(twin);
            expect(ATTRIBUTE_MAP[key].requestOnly).toBeUndefined();
            expect(CANONICAL_KEYS.has(twin)).toBe(true);
            expect(ATTRIBUTE_MAP[twin].requestOnly).toBe(true);
            // One disclosure under two names, so one registry row and one charge.
            expect(marketplaceKeyFor(twin)).toBe(marketplaceKeyFor(key));
        }
    });

    it('routes an *_id key to the field the enclave actually certifies', () => {
        // prove_field opens a commitment by the verifier's own field name. The
        // `_id` suffix is a canonical spelling the enclave has never seen, and
        // asking for it is rejected as an uncertified field.
        expect(certifiedFieldFor('given_name_id')).toBe('given_name');
        expect(certifiedFieldFor('family_name_id')).toBe('family_name');
        expect(certifiedFieldFor('birthdate_id')).toBe('birthdate');
        expect(certifiedFieldFor('nationality_id')).toBe('nationality');
        expect(certifiedFieldFor('doc_expiry')).toBe('doc_expiry');
    });

    it('marks the ID portrait as a value the enclave will not re-certify', () => {
        // The verifier commits to DG2 so a fresh selfie can be matched against
        // it. Until the marketplace prices the disclosure there is no voucher to
        // authorise a fresh certification, so the wallet relays its stored copy.
        // Claiming a token here would make every request for the ID photo fail
        // silently, which is exactly what it used to do.
        expect(disclosesAsToken('picture_id')).toBe(false);
        expect(disclosesAsToken('given_name_id')).toBe(true);
        expect(ATTRIBUTE_MAP['picture_id'].marketplace).toBeUndefined();
    });

    it('marks the derived insights as having no stored value', () => {
        // The enclave computes these from the identity receipt at disclosure
        // time. A wallet that treated them as profile fields would prompt the
        // holder for an "age band" they can never type in.
        for (const key of ['age_band', 'document_valid']) {
            expect(isDerived(key)).toBe(true);
            expect(ATTRIBUTE_MAP[key].requestOnly).toBe(true);
        }
        expect(isDerived('age_over_18')).toBe(false);
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
            'birthdate_id',
            'nationality_id',
            'picture_id',
        ]) {
            expect(CANONICAL_KEYS.has(key)).toBe(true);
        }
    });
});
