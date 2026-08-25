// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Guards on how the approval screen identifies an app.
 *
 * Two of these protect a security property rather than a nicety. The slug is
 * derived from a hostname an attacker chooses, so it must never be used to
 * build a request path unsanitised; and a missing listing must resolve to
 * "we cannot name this app" rather than to any name at all, because a
 * plausible-looking name on a trust screen is worse than none.
 */

import { slugForHost, sourceLabel, sourceUrl, type StoreListing } from '@/services/store-listing';

describe('slugForHost', () => {
    it('takes the first label of an app host', () => {
        expect(slugForHost('drive.apps.privasys.org')).toBe('drive');
        expect(slugForHost('web-search-brave.apps-test.privasys.org')).toBe('web-search-brave');
    });

    it('lowercases, because the store slug is lower case', () => {
        expect(slugForHost('Drive.apps.privasys.org')).toBe('drive');
    });

    it('returns nothing for a bare domain, which has no slug to speak of', () => {
        expect(slugForHost('privasys.org')).toBeUndefined();
        expect(slugForHost('localhost')).toBeUndefined();
    });

    it('rejects a label that is not a plain slug', () => {
        // The host comes from a QR code an attacker controls, and the result is
        // interpolated into a request path. Anything that could traverse or
        // inject has to be refused here, not encoded away downstream.
        expect(slugForHost('../admin.apps.privasys.org')).toBeUndefined();
        expect(slugForHost('a b.apps.privasys.org')).toBeUndefined();
        expect(slugForHost('-lead.apps.privasys.org')).toBeUndefined();
        expect(slugForHost('.apps.privasys.org')).toBeUndefined();
    });
});

describe('sourceUrl', () => {
    const withCommit = { reproducibility: { commit_url: 'https://github.com/Privasys/drive' } } as StoreListing;

    it('prefers the store commit URL', () => {
        expect(sourceUrl(withCommit, 'https://github.com/Privasys/other/releases/tag/v1')).toBe(
            'https://github.com/Privasys/drive',
        );
    });

    it('falls back to the published release when the store has no commit', () => {
        // Real case: an app built from a published package rather than source
        // has no commit_url in its listing (verified against the live store),
        // so the release page is the only reviewable link there is.
        expect(sourceUrl({ reproducibility: {} } as StoreListing, 'https://github.com/Privasys/x/releases')).toBe(
            'https://github.com/Privasys/x/releases',
        );
    });

    it('is undefined when neither is known, so the row is dropped', () => {
        expect(sourceUrl(null, undefined)).toBeUndefined();
    });
});

describe('sourceLabel', () => {
    it('shortens a GitHub URL to owner/repo', () => {
        expect(sourceLabel('https://github.com/Privasys/drive')).toBe('Privasys/drive');
        expect(sourceLabel('https://github.com/Privasys/drive/releases/tag/v0.1.26')).toBe('Privasys/drive');
    });

    it('falls back to the host for anything else', () => {
        expect(sourceLabel('https://git.example.com/team/app')).toBe('git.example.com');
    });

    it('returns the input unchanged when it will not parse', () => {
        expect(sourceLabel('not a url')).toBe('not a url');
    });
});
