// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What the wallet will and will not put on a capability screen.
 *
 * The screen grants an app durable authority over the holder's data, so
 * everything on it must be something the wallet either verified itself or can
 * describe from its own closed vocabulary. A request that supplies its own
 * words is the same phishing surface as one that supplies its own name, and it
 * cannot be translated into the other 24 locales either.
 */

jest.mock('../../modules/native-ratls/src/index', () => ({ makeRaTlsFetch: jest.fn() }));
jest.mock('@/services/platform-token', () => ({ getPlatformToken: jest.fn() }));

import {
    parsePendingCapability,
    expiryFor,
    CapabilityError,
    PERMISSIONS,
} from '@/services/capabilities';
import { attestationMatchesResolution } from '@/services/app-resolve';

const valid = () => ({
    nonce: 'a'.repeat(64),
    binding_pubkey: 'YmluZGluZy1rZXk=',
    resource_app: 'privasys-drive',
    capability: {
        kind: 'storage.folder',
        permissions: ['read', 'write'],
        resource_label: 'Harness',
        request: { folder: 'Harness' },
    },
});

describe('parsePendingCapability', () => {
    it('accepts a well-formed request', () => {
        const p = parsePendingCapability(valid());
        expect(p.capability.kind).toBe('storage.folder');
        expect(p.capability.permissions).toEqual(['read', 'write']);
        expect(p.capability.resource_label).toBe('Harness');
        expect(p.capability.request).toEqual({ folder: 'Harness' });
    });

    // An unknown kind has no wallet-owned explanation, so there is no honest
    // screen to draw for it. Refuse rather than render the raw string.
    it('refuses a kind it cannot explain', () => {
        const r = valid();
        r.capability.kind = 'vault.sign';
        expect(() => parsePendingCapability(r)).toThrow(CapabilityError);
    });

    it('refuses a permission outside the closed vocabulary', () => {
        const r = valid();
        r.capability.permissions = ['read', 'administer'];
        expect(() => parsePendingCapability(r)).toThrow(/cannot describe/);
    });

    it('refuses a request asking for nothing', () => {
        const r = valid();
        r.capability.permissions = [];
        expect(() => parsePendingCapability(r)).toThrow(/no permissions/);
    });

    // The binding key is the credential being authorised. Without one there is
    // nothing to authorise, and a screen would be describing an empty grant.
    it('refuses a request with no binding key', () => {
        const r = valid();
        r.binding_pubkey = '';
        expect(() => parsePendingCapability(r)).toThrow(/binding key/);
    });

    it('refuses a request that names no resource service', () => {
        const r = valid();
        r.resource_app = '';
        expect(() => parsePendingCapability(r)).toThrow(/resource service/);
    });

    it('refuses a request with no nonce', () => {
        const r = valid();
        r.nonce = '';
        expect(() => parsePendingCapability(r)).toThrow(/nonce/);
    });

    it('refuses a resource label that is blank or only whitespace', () => {
        const r = valid();
        r.capability.resource_label = '   ';
        expect(() => parsePendingCapability(r)).toThrow(/names no resource/);
    });

    it.each([null, undefined, 'nope', 42])('refuses %p', (bad) => {
        expect(() => parsePendingCapability(bad)).toThrow(CapabilityError);
    });

    // The wallet forwards `request` verbatim and never reads it. Inspecting it
    // is the RESOURCE SERVICE's job, which is where the boundary check lives.
    it('forwards an unrecognised request body untouched', () => {
        const r = valid();
        r.capability.request = { folder: 'Harness', somethingElse: { nested: true } } as never;
        expect(parsePendingCapability(r).capability.request).toEqual({
            folder: 'Harness',
            somethingElse: { nested: true },
        });
    });
});

describe('expiry', () => {
    // Chosen by the wallet, never by the requester, so nobody can ask for an
    // unbounded capability.
    it('is a fixed lifetime per kind, from now', () => {
        const now = 1_800_000_000_000;
        expect(expiryFor('storage.folder', now)).toBe(now / 1000 + 90 * 24 * 60 * 60);
    });
});

describe('attestationMatchesResolution', () => {
    const APP = '3f6d1a0e-0000-4000-8000-000000000001';
    const oids = (hex: string) => [{ oid: '1.3.6.1.4.1.65230.4.1', label: 'app id', value_hex: hex }];
    const att = (hex: string) => ({ custom_oids: oids(hex) }) as never;

    it('matches when the attested app id is the one resolved', () => {
        expect(attestationMatchesResolution(att('3f6d1a0e000040008000000000000001'), {
            app_id: APP, name: 'd', display_name: 'D', hostname: 'h', image_digest: 'x', is_enclave: true,
        })).toBe(true);
    });

    it('rejects a host that attests as a different app', () => {
        expect(attestationMatchesResolution(att('ffffffff000040008000000000000001'), {
            app_id: APP, name: 'd', display_name: 'D', hostname: 'h', image_digest: 'x', is_enclave: true,
        })).toBe(false);
    });

    // Fails closed. Both values exist on any deployed app, so an absence means
    // something is wrong rather than something is old.
    it('fails closed when either side has no app id', () => {
        expect(attestationMatchesResolution(att(''), {
            app_id: APP, name: 'd', display_name: 'D', hostname: 'h', image_digest: 'x', is_enclave: true,
        })).toBe(false);
        expect(attestationMatchesResolution(att('3f6d1a0e000040008000000000000001'), {
            name: 'd', display_name: 'D', hostname: 'h', image_digest: 'x', is_enclave: true,
        })).toBe(false);
        expect(attestationMatchesResolution(null, null)).toBe(false);
    });
});

describe('the permission vocabulary', () => {
    // Adding one is a wallet change with 25 translations, deliberately: it is a
    // new sentence about the holder's data.
    it('is exactly read, write and delete', () => {
        expect([...PERMISSIONS]).toEqual(['read', 'write', 'delete']);
    });
});
