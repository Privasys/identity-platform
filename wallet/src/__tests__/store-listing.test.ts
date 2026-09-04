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

import type { WorkloadRelease } from '@/services/release-provenance';
import { slugForHost, sourceLabel, sourceRow, sourceUrl, type StoreListing } from '@/services/store-listing';

describe('slugForHost', () => {
    it('takes the first label of an app host', () => {
        // The live host and slug for Privasys Drive, checked against the store
        // on 2026-08-26. The two have to agree or the app silently falls back
        // to "not published" on its own approval screen, which is exactly the
        // bug this pins: the enclave host is privasys-drive.apps…, NOT drive.apps…
        expect(slugForHost('privasys-drive.apps.privasys.org')).toBe('privasys-drive');
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
    it('returns the store commit URL', () => {
        const listing = { reproducibility: { commit_url: 'https://github.com/Privasys/drive' } } as StoreListing;
        expect(sourceUrl(listing)).toBe('https://github.com/Privasys/drive');
    });

    it('is undefined for an app built from a published image', () => {
        // The real shape of Privasys Drive in the live store: source_type
        // "package", a digest-pinned container image, and no commit_url. The
        // row must DISAPPEAR rather than borrow the release URL, because that
        // one can be a GHCR package page and "Source code" pointing at a
        // package page is a claim we cannot support on a trust screen.
        const listing = {
            reproducibility: {
                source_type: 'package',
                container_image: 'ghcr.io/privasys/drive@sha256:892d8e8b',
                enclave_os_release_url: 'https://github.com/Privasys/enclave-os-virtual/releases',
            },
        } as StoreListing;
        expect(sourceUrl(listing)).toBeUndefined();
    });

    it('is undefined with no listing at all', () => {
        expect(sourceUrl(null)).toBeUndefined();
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

describe('sourceRow', () => {
    const workload = {
        url: 'https://github.com/Privasys/wasm-app-example/commit/9f2c1ab4d3e5f60718293a4b5c6d7e8f90a1b2c3',
        commit_url: 'https://github.com/Privasys/wasm-app-example/commit/9f2c1ab4d3e5f60718293a4b5c6d7e8f90a1b2c3',
        commit: '9f2c1ab4d3e5f60718293a4b5c6d7e8f90a1b2c3',
    } as WorkloadRelease;

    it('names the commit for an app with no store listing', () => {
        // The case this exists for: an unpublished app. There is no listing to
        // read, so the row used to vanish for exactly the apps a holder has
        // least other reason to trust.
        expect(sourceRow(null, workload)).toEqual({
            url: workload.commit_url,
            label: 'Privasys/wasm-app-example@9f2c1ab',
        });
    });

    it('prefers the store listing when the app published one', () => {
        const listing = { reproducibility: { commit_url: 'https://github.com/Privasys/drive' } } as StoreListing;
        expect(sourceRow(listing, workload)).toEqual({
            url: 'https://github.com/Privasys/drive',
            label: 'Privasys/drive',
        });
    });

    it('is undefined when neither side has a commit', () => {
        // A build run URL is not source code, so a workload that carries only
        // one leaves the row off rather than pointing "Source code" at a log.
        const runOnly = { build_run_url: 'https://github.com/Privasys/reproducible-app-builder/actions/runs/1' } as WorkloadRelease;
        expect(sourceRow(null, runOnly)).toBeUndefined();
        expect(sourceRow(null, null)).toBeUndefined();
    });
});
