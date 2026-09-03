// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The update gate, and the ways it must refuse to fire.
 *
 * This is the one feature in the wallet whose failure mode is locking someone
 * out of their own identity, so most of what follows is about NOT showing the
 * wall: a malformed document, an unknown schema, a floor with no explanation,
 * an entry for the other platform. Every one of those has to mean "carry on".
 *
 * The exception, and the reason a verdict is persisted at all, is suppression.
 * An attacker who can drop a request would otherwise keep a wallet on a
 * vulnerable version for ever, so a wall already raised survives a failed
 * fetch.
 *
 * The document is served over ordinary TLS, so the signature is what stands
 * between a forged certificate and a walled installed base. It is checked
 * before any content is read, and every way it can fail lands in the same place
 * as an unreachable server.
 */

const storage: Record<string, string> = {};
jest.mock('@/utils/storage', () => ({
    getItemAsync: jest.fn(async (k: string) => storage[k] ?? null),
    setItemAsync: jest.fn(async (k: string, v: string) => {
        storage[k] = v;
    }),
    deleteItemAsync: jest.fn(async (k: string) => {
        delete storage[k];
    }),
}));

// Only Platform.OS is reached, and pulling the real react-native in needs a
// runtime this suite has no use for.
jest.mock('react-native', () => ({ Platform: { OS: 'ios' } }));

// The shipped bundle pins no key, which keeps the gate inert. Pin a throwaway
// one here so the rest of the behaviour is reachable. Computed inside the
// factory because jest hoists this above every const in the file.
jest.mock('@/services/version-signing-keys', () => {
    const { ed25519 } = require('@noble/curves/ed25519.js');
    const pk = ed25519.getPublicKey(new Uint8Array(32).fill(7));
    const b64u = Buffer.from(pk).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return { VERSION_SIGNING_KEYS: { 'test-key': b64u } };
});

jest.mock('expo-constants', () => ({
    __esModule: true,
    default: { expoConfig: { version: '1.3.90', extra: { CODE_VERSION: '1.3.90' } } },
}));

import { ed25519 } from '@noble/curves/ed25519.js';

import {
    checkForUpdate,
    compareVersions,
    dismissNotice,
    openEnvelope,
    parseManifest,
    type UpdateLevel,
} from '@/services/app-version';

/** The key the mocked pin above trusts, and one it does not. */
const SEED = new Uint8Array(32).fill(7);
const UNTRUSTED_SEED = new Uint8Array(32).fill(9);

function b64u(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const TRUSTED_KEYS = { 'test-key': b64u(ed25519.getPublicKey(SEED)) };

/** Wrap a document the way the deploy signs it. */
function seal(doc: unknown, seed: Uint8Array = SEED, keyId = 'test-key') {
    const payload = new TextEncoder().encode(JSON.stringify(doc));
    return { keyId, payload: b64u(payload), sig: b64u(ed25519.sign(payload, seed)) };
}

const PLATFORM = 'ios';

function manifest(over: Record<string, unknown> = {}) {
    return {
        schema: 1,
        issuedAt: '2026-08-29T10:00:00Z',
        platforms: { ios: { minimum: '1.3.92', level: 'required' } },
        notice: {
            id: 'passport-fix',
            text: {
                'en-GB': {
                    title: 'Update to keep verifying identity',
                    body: 'Reading a passport cannot complete on this version.',
                    changes: ['Identity verification will not finish.'],
                },
            },
        },
        ...over,
    };
}

const opts = { platform: PLATFORM, version: '1.3.90', language: 'en-GB' };

beforeEach(() => {
    for (const k of Object.keys(storage)) delete storage[k];
    jest.restoreAllMocks();
    jest.spyOn(console, 'warn').mockImplementation(() => undefined);
});

describe('compareVersions', () => {
    it.each([
        ['1.3.90', '1.3.92', -1],
        ['1.3.92', '1.3.90', 1],
        ['1.3.92', '1.3.92', 0],
        ['1.4.0', '1.3.99', 1],
        ['2.0.0', '1.99.99', 1],
        // Zero-padding: a two-component version is not "greater" than a three.
        ['1.3', '1.3.0', 0],
        ['1.3', '1.3.1', -1],
    ])('%s vs %s', (a, b, expected) => {
        expect(Math.sign(compareVersions(a, b))).toBe(expected);
    });

    // Garbage compares as the lowest build, which errs toward showing a notice
    // rather than silently clearing a floor.
    it.each([['', '1.0.0'], ['not-a-version', '1.0.0'], ['1.x.3', '1.1.0']])(
        'treats %s as lower than %s',
        (a, b) => {
            expect(compareVersions(a, b)).toBeLessThan(0);
        },
    );
});

describe('parseManifest', () => {
    it('raises a notice when the build is below the floor', () => {
        const out = parseManifest(manifest(), opts);
        expect(out?.notice?.level).toBe('required');
        expect(out?.notice?.minimum).toBe('1.3.92');
        expect(out?.notice?.current).toBe('1.3.90');
        expect(out?.notice?.text.title).toContain('Update');
    });

    it('says nothing when the build meets the floor', () => {
        expect(parseManifest(manifest(), { ...opts, version: '1.3.92' })?.notice).toBeNull();
        expect(parseManifest(manifest(), { ...opts, version: '1.4.0' })?.notice).toBeNull();
    });

    it('treats an unknown level as the gentler one', () => {
        const out = parseManifest(
            manifest({ platforms: { ios: { minimum: '1.3.92', level: 'apocalyptic' } } }),
            opts,
        );
        // Anything the app does not recognise must not become a wall.
        expect(out?.notice?.level).toBe<UpdateLevel>('recommended');
    });

    it('ignores a floor set for the other platform', () => {
        const out = parseManifest(
            manifest({ platforms: { android: { minimum: '9.9.9', level: 'required' } } }),
            opts,
        );
        expect(out?.notice).toBeNull();
    });

    // Every one of these must mean "carry on", never "wall the user".
    it.each([
        ['null', null],
        ['a string', 'nope'],
        ['an array', []],
        ['an empty object', {}],
        ['a future schema', { schema: 2, issuedAt: '2026-08-29T10:00:00Z' }],
        ['no schema', { issuedAt: '2026-08-29T10:00:00Z' }],
        ['an unparseable date', manifest({ issuedAt: 'soon' })],
        ['no date', manifest({ issuedAt: undefined })],
    ])('refuses to act on %s', (_label, doc) => {
        const out = parseManifest(doc, opts);
        expect(out === null || out.notice === null).toBe(true);
    });

    it.each([
        ['no notice at all', manifest({ notice: undefined })],
        ['no text', manifest({ notice: { id: 'x' } })],
        ['a language we cannot read and no English', manifest({ notice: { id: 'x', text: { xx: { title: 'a', body: 'b' } } } })],
        ['an empty title', manifest({ notice: { id: 'x', text: { 'en-GB': { title: '  ', body: 'b' } } } })],
        ['an empty body', manifest({ notice: { id: 'x', text: { 'en-GB': { title: 'a', body: '' } } } })],
    ])('shows no notice when the floor comes with %s', (_label, doc) => {
        // A floor with no explanation is not shown. Asking someone to act with
        // no reason is how people learn to ignore this screen.
        expect(parseManifest(doc, opts)?.notice).toBeNull();
    });

    it('falls back through the bare language to English', () => {
        const doc = manifest({
            notice: {
                id: 'x',
                text: {
                    fr: { title: 'Mise à jour', body: 'Corps', changes: [] },
                    'en-GB': { title: 'Update', body: 'Body', changes: [] },
                },
            },
        });
        expect(parseManifest(doc, { ...opts, language: 'fr-CA' })?.notice?.text.title).toBe('Mise à jour');
        expect(parseManifest(doc, { ...opts, language: 'de' })?.notice?.text.title).toBe('Update');
    });

    it('drops non-string entries from the changes list', () => {
        const doc = manifest({
            notice: {
                id: 'x',
                text: { 'en-GB': { title: 'a', body: 'b', changes: ['real', '', 42, null, 'also real'] } },
            },
        });
        expect(parseManifest(doc, opts)?.notice?.text.changes).toEqual(['real', 'also real']);
    });
});

describe('checkForUpdate', () => {
    function serve(doc: unknown, ok = true) {
        global.fetch = jest.fn(async () => ({ ok, json: async () => seal(doc) })) as unknown as typeof fetch;
    }

    /** Serve something that is not a validly signed envelope. */
    function serveRaw(body: unknown) {
        global.fetch = jest.fn(async () => ({ ok: true, json: async () => body })) as unknown as typeof fetch;
    }

    it('returns the notice the manifest describes', async () => {
        serve(manifest());
        await expect(checkForUpdate('en-GB')).resolves.toMatchObject({ level: 'required' });
    });

    it('says nothing when the network is unreachable and nothing was known', async () => {
        global.fetch = jest.fn(async () => {
            throw new Error('offline');
        }) as unknown as typeof fetch;
        await expect(checkForUpdate('en-GB')).resolves.toBeNull();
    });

    // Suppression is the attack a signature cannot fix, so the verdict persists.
    it('keeps a wall raised when a later fetch fails', async () => {
        serve(manifest());
        await checkForUpdate('en-GB');

        global.fetch = jest.fn(async () => {
            throw new Error('offline');
        }) as unknown as typeof fetch;
        await expect(checkForUpdate('en-GB')).resolves.toMatchObject({ level: 'required' });
    });

    it('lifts the wall when a newer manifest clears the floor', async () => {
        serve(manifest());
        await checkForUpdate('en-GB');

        serve(manifest({ issuedAt: '2026-08-30T10:00:00Z', platforms: { ios: { minimum: '1.3.0' } } }));
        await expect(checkForUpdate('en-GB')).resolves.toBeNull();
    });

    // Replaying a captured older document must not lower a floor.
    it('ignores a manifest older than the one already seen', async () => {
        serve(manifest());
        await checkForUpdate('en-GB');

        serve(manifest({ issuedAt: '2026-08-01T10:00:00Z', platforms: { ios: { minimum: '1.0.0' } } }));
        await expect(checkForUpdate('en-GB')).resolves.toMatchObject({ level: 'required' });
    });

    it('honours a dismissal of a recommended notice', async () => {
        serve(manifest({ platforms: { ios: { minimum: '1.3.92', level: 'recommended' } } }));
        const notice = await checkForUpdate('en-GB');
        expect(notice).not.toBeNull();

        await dismissNotice(notice!.id);
        await expect(checkForUpdate('en-GB')).resolves.toBeNull();
    });

    it('shows a dismissed notice again once it escalates to required', async () => {
        serve(manifest({ platforms: { ios: { minimum: '1.3.92', level: 'recommended' } } }));
        const notice = await checkForUpdate('en-GB');
        await dismissNotice(notice!.id);

        serve(manifest({ issuedAt: '2026-08-30T10:00:00Z' })); // same id, now required
        await expect(checkForUpdate('en-GB')).resolves.toMatchObject({ level: 'required' });
    });

    it('nags again for a different notice', async () => {
        serve(manifest({ platforms: { ios: { minimum: '1.3.92', level: 'recommended' } } }));
        await dismissNotice((await checkForUpdate('en-GB'))!.id);

        serve(
            manifest({
                issuedAt: '2026-08-30T10:00:00Z',
                platforms: { ios: { minimum: '1.3.93', level: 'recommended' } },
                notice: {
                    id: 'something-else',
                    text: { 'en-GB': { title: 'New', body: 'Reason', changes: [] } },
                },
            }),
        );
        await expect(checkForUpdate('en-GB')).resolves.toMatchObject({ id: 'something-else' });
    });

    it('ignores a non-2xx response', async () => {
        serve(manifest(), false);
        await expect(checkForUpdate('en-GB')).resolves.toBeNull();
    });

    // The document is what a forged certificate would replace, so an
    // unverifiable one has to be worth exactly as much as no document at all.
    it.each([
        ['an unsigned document', (m: unknown) => m],
        ['a signature from an untrusted key', (m: unknown) => seal(m, UNTRUSTED_SEED)],
        ['a key this build does not carry', (m: unknown) => seal(m, SEED, 'some-other-key')],
    ])('ignores %s', async (_label, wrap) => {
        serveRaw(wrap(manifest()));
        await expect(checkForUpdate('en-GB')).resolves.toBeNull();
    });

    it('ignores a payload edited after signing', async () => {
        const sealed = seal(manifest());
        const tampered = manifest({ platforms: { ios: { minimum: '9.9.9', level: 'required' } } });
        // Same signature, different payload: exactly what a middlebox would do.
        serveRaw({ ...sealed, payload: b64u(new TextEncoder().encode(JSON.stringify(tampered))) });
        await expect(checkForUpdate('en-GB')).resolves.toBeNull();
    });
});

describe('the keys pinned in this bundle', () => {
    // A mistyped pin is silent: nothing breaks, no wallet complains, and every
    // floor published afterwards is quietly ignored. The deploy has the other
    // half of this guard, asserting the CI signing key's public half is one of
    // these.
    const { VERSION_SIGNING_KEYS } = jest.requireActual<{
        VERSION_SIGNING_KEYS: Record<string, string>;
    }>('@/services/version-signing-keys');

    it('are all real Ed25519 public keys', () => {
        const entries = Object.entries(VERSION_SIGNING_KEYS);
        for (const [keyId, encoded] of entries) {
            const raw = Buffer.from(encoded, 'base64url');
            expect(`${keyId}: ${raw.length} bytes`).toBe(`${keyId}: 32 bytes`);
            // Round-trips, so no stray padding or a non-base64url alphabet
            // slipped in from a copy-paste.
            expect(raw.toString('base64url')).toBe(encoded);
            // And decodes to a point on the curve: 32 random bytes usually do
            // not, so this catches a truncated or scrambled paste.
            expect(() => ed25519.Point.fromBytes(new Uint8Array(raw))).not.toThrow();
        }
    });
});

describe('openEnvelope', () => {
    it('returns the payload text when the signature checks out', () => {
        expect(openEnvelope(seal({ hello: 'there' }), TRUSTED_KEYS)).toBe('{"hello":"there"}');
    });

    // An empty pin map is the shipped default, and it must leave the gate inert
    // rather than open.
    it('verifies nothing when no key is pinned', () => {
        expect(openEnvelope(seal({ hello: 'there' }), {})).toBeNull();
    });

    it.each([
        ['null', null],
        ['a string', 'nope'],
        ['an empty object', {}],
        ['a missing signature', { keyId: 'test-key', payload: 'e30' }],
        ['a missing payload', { keyId: 'test-key', sig: 'AAAA' }],
        ['a non-string keyId', { keyId: 1, payload: 'e30', sig: 'AAAA' }],
        ['unparseable base64', { keyId: 'test-key', payload: '!!!!', sig: '!!!!' }],
    ])('refuses %s', (_label, raw) => {
        expect(openEnvelope(raw, TRUSTED_KEYS)).toBeNull();
    });
});
