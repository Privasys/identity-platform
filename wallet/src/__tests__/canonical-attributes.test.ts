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
    attributeAssurance, certifiedFieldFor, disclosesAsToken, govValueKey, isDerived,
    marketplaceKeyFor
} from '@/services/attributes';
import type { ProfileAttribute, UserProfile } from '@/stores/profile';

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
            'birthdate_id',
            'doc_expiry',
            'document_valid',
            'family_name_id',
            'given_name_id',
            'nationality_id',
            'personal_number',
            'picture_id',
            'place_of_birth',
        ]);
        for (const a of paid) {
            expect(attributeAssurance(a.key)).toBe(GOV_VERIFIED);
            expect(a.marketplace!.key).toBe(`privasys:${certifiedFieldFor(a.key)}`);
            expect(a.marketplace!.billable).toBe(true);
            // Pricing a key means making it request-only in the same change. A
            // priced key left on a scope-derived set charges every identity
            // request for a disclosure nobody asked for, which is how
            // doc_expiry, place_of_birth and personal_number would have started
            // billing the moment migration 076 seeded their rows.
            //
            // age_over_18/21 are the exception, and only because they predate
            // the rule: they ARE the identity baseline, priced and scope-reachable
            // since the marketplace shipped, and making them request-only now
            // would drop them from every client that has ever asked for identity.
            const baseline = a.key === 'age_over_18' || a.key === 'age_over_21';
            expect(ATTRIBUTE_MAP[a.key].requestOnly ?? false).toBe(!baseline);
        }
    });

    it('leaves the unpriced document fields without a marketplace entry', () => {
        // These come off the chip alongside a priced insight. Naming one in a
        // reservation fails the whole authorization as an unknown attribute, so
        // an attribute the enclave certifies but the registry has not priced
        // must stay unnamed here until a migration seeds its row.
        for (const key of ['document_number', 'document_type', 'issuing_state', 'sex']) {
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

    it('splits the two keys that were minted government-backed', () => {
        // birthdate and nationality predate the convention. They are dual now:
        // the bare key is the self-asserted reading, free, and still reachable
        // from the identity scope it has always been in, while the passport
        // reading moved to the `_id` spelling. This is a BREAKING change for a
        // client that named the bare key, which is why it ships with the
        // migrations that rewrite a registered whitelist.
        for (const key of ['birthdate', 'nationality']) {
            const twin = `${key}_id`;
            expect(ATTRIBUTE_MAP[key].govKey).toBe(twin);
            expect(ATTRIBUTE_MAP[key].supersededBy).toBeUndefined();
            expect(attributeAssurance(key)).toBe(SELF_ASSERTED);
            expect(ATTRIBUTE_MAP[key].scope).toBe('identity');
            expect(ATTRIBUTE_MAP[key].requestOnly).toBeUndefined();
            expect(ATTRIBUTE_MAP[key].marketplace).toBeUndefined();

            expect(CANONICAL_KEYS.has(twin)).toBe(true);
            expect(attributeAssurance(twin)).toBe(GOV_VERIFIED);
            expect(ATTRIBUTE_MAP[twin].requestOnly).toBe(true);
            // The twin keeps the row the bare key was sold under, so a voucher
            // or a share link naming privasys:birthdate buys what it always did.
            expect(marketplaceKeyFor(twin)).toBe(`privasys:${key}`);
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

    it('certifies the ID portrait like any other document field', () => {
        // The portrait was relayed from the wallet's own copy while the enclave
        // had no commitment it could re-open for a disclosure. identity-verifier
        // v0.6.3 gave picture_id its own salted commitment and migration 076
        // priced it, so the wallet calls prove_field and the relying party gets a
        // fresh signature rather than a stored photo.
        //
        // Both halves had to be true before this flipped: relaying carries gov
        // provenance and no signature, and charging for one would sell an enclave
        // signature nobody produced.
        expect(disclosesAsToken('picture_id')).toBe(true);
        expect(disclosesAsToken('given_name_id')).toBe(true);
        expect(marketplaceKeyFor('picture_id')).toBe('privasys:picture_id');
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

    it('answers a request for the new spelling from a profile holding the old one', () => {
        // The holder-side half of the split. A wallet that verified a passport
        // before birthdate gained a twin stored the value under the bare key, and
        // that profile is deliberately not migrated: refusing the disclosure
        // would ask the holder to re-scan a document already certified.
        const attr = (over: Partial<ProfileAttribute>): ProfileAttribute => ({
            key: 'x', label: 'X', value: 'v', source: 'manual', verified: false, ...over
        });
        const profile = {
            attributes: [
                attr({ key: 'birthdate', value: '1980-01-01', source: 'document', verified: true }),
                attr({ key: 'given_name', value: 'Bertrand' })
            ]
        } as unknown as UserProfile;

        expect(govValueKey(profile, 'birthdate_id')).toBe('birthdate');
        // And the safety of that fallback: a name the holder typed is not a name
        // a passport certifies, however similar the two keys look.
        expect(govValueKey(profile, 'given_name_id')).toBeUndefined();
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
