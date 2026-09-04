// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Which hosts the wallet expects enclave evidence from.
 *
 * RA-TLS v2 makes the caller declare that before it connects, so the wallet
 * decides from the hostname rather than by inspecting a certificate and seeing
 * what came back. Every Privasys enclave lives under `.apps.privasys.org` or,
 * for the test fleet, `.apps.test.privasys.org`. Nothing else does, including
 * our own non-enclave properties.
 *
 * The input is a hostname out of a scanned QR, which is to say attacker
 * controlled, so most of what follows is the near-misses: a suffix that appears
 * somewhere other than the end, a lookalike registered domain, the bare
 * apps.privasys.org.
 *
 * Both answers fail safe, which is why this is a hostname check and not
 * something cleverer. A real enclave published elsewhere is treated as an
 * ordinary host: less trust claimed than is available. A non-enclave under the
 * suffix is asked for evidence it cannot give and the handshake fails. Neither
 * shows an unattested peer to the holder as attested.
 */

// attestation.ts pulls in the RA-TLS native module, which reaches for the React
// Native runtime at import time. The rule under test touches none of it.
jest.mock('../../modules/native-ratls/src/index', () => ({
    inspect: jest.fn(),
    verify: jest.fn(),
    post: jest.fn(),
    request: jest.fn(),
}));
jest.mock('expo-crypto', () => ({
    getRandomBytes: jest.fn((n: number) => new Uint8Array(n)),
}));

import { isAttestableHost } from '@/services/attestation';

describe('isAttestableHost', () => {
    it.each([
        'privasys-drive.apps.privasys.org',
        'privasys-identity-verifier.apps.privasys.org',
        'confidential-ai.apps.privasys.org',
        // Deeper labels are still under the suffix.
        'a.b.apps.privasys.org',
        // The test fleet. A separate suffix, not a subdomain of the production
        // one: x.apps.test.privasys.org does not end in .apps.privasys.org.
        'privasys-drive.apps.test.privasys.org',
        'a.b.apps.test.privasys.org',
    ])('expects evidence from %s', (host) => {
        expect(isAttestableHost(host)).toBe(true);
    });

    it.each([
        // The identity provider. Not an enclave, and inspecting it was always
        // theatre: it returned a quote-less certificate that proved nothing.
        ['the identity provider', 'privasys.id'],
        ['the marketing site', 'privasys.org'],
        ['the developer portal', 'api.developer.privasys.org'],
        ['an ordinary FIDO2 relying party', 'github.com'],
        // The bare domains host no enclave.
        ['the enclave parent domain itself', 'apps.privasys.org'],
        ['the test enclave parent domain itself', 'apps.test.privasys.org'],
        // Ours, not an enclave: the suffix is deliberately narrower than the
        // registrable domain.
        ['the test environment root', 'test.privasys.org'],
    ])('does not expect evidence from %s', (_label, host) => {
        expect(isAttestableHost(host)).toBe(false);
    });

    // The reason this is a suffix test and not a substring one.
    it.each([
        ['the suffix in the middle', 'x.apps.privasys.org.evil.com'],
        ['a lookalike registrable domain', 'apps-privasys.org'],
        ['a lookalike with the right tail', 'notapps.privasys.org.attacker.net'],
        ['the suffix as a prefix', 'apps.privasys.org.co'],
        // No leading dot means this is one registered name, not a subdomain.
        ['a name merely ending in the same letters', 'evilapps.privasys.org'],
        ['the test suffix in the middle', 'x.apps.test.privasys.org.evil.com'],
        ['a lookalike of the test suffix', 'evilapps.test.privasys.org'],
        ['test inserted where it does not belong', 'x.test.apps.privasys.org.co'],
    ])('rejects %s', (_label, host) => {
        expect(isAttestableHost(host)).toBe(false);
    });

    // All three arrive from payloads the wallet does not control.
    it.each([
        ['upper case', 'Privasys-Drive.Apps.Privasys.Org'],
        ['a trailing root dot', 'privasys-drive.apps.privasys.org.'],
        ['an explicit port', 'privasys-drive.apps.privasys.org:443'],
        ['surrounding whitespace', '  privasys-drive.apps.privasys.org  '],
    ])('normalises %s', (_label, host) => {
        expect(isAttestableHost(host)).toBe(true);
    });

    it.each([
        ['an empty string', ''],
        ['whitespace', '   '],
        ['undefined', undefined],
        ['null', null],
    ])('says no to %s rather than throwing', (_label, host) => {
        expect(isAttestableHost(host as unknown as string)).toBe(false);
    });
});
