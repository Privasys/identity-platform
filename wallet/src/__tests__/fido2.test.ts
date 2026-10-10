/**
 * FIDO2 service unit tests.
 *
 * Mocks the native modules and checks that the registration and
 * authentication ceremonies produce the standard WebAuthn messages the IdP
 * parses with go-webauthn: query parameters on the path, a JSON body with
 * base64url fields, a CBOR attestation object with the wallet's AAGUID.
 *
 * These tests catch:
 *  - crypto.subtle usage (unavailable in React Native)
 *  - base64url encoding errors
 *  - CBOR attestation object and authenticatorData structure
 *  - the identity handle and phrase options a registration carries
 */

// ── Mock native modules BEFORE importing fido2 ─────────────────────────
// Fake P-256 uncompressed public key (65 bytes: 0x04 || x || y)
const FAKE_PUB_KEY_B64URL =
    'BFqR7zQvBgrYjqGOcnqHJbquGFhdOvEyLMOcEMtzmEiQPQR3bwC3EKw2TdSNJrVWBTMbr_UDfj8r0lic0wu7Lg';
const FAKE_SIGNATURE_B64URL = 'MEUCIQC1234fakesignatureAIBcde567890';

const mockResponses: Record<string, object> = {};
const mockCaptured: Array<{ host: string; port: number; path: string; route: string; body: any }> = [];

jest.mock('react-native', () => ({ Platform: { OS: 'ios' } }));
jest.mock('@/stores/settings', () => ({ useSettingsStore: { getState: () => ({}) } }));
jest.mock('../services/attestation', () => ({ isAttestableHost: () => false }));
jest.mock('../../modules/native-ratls/src/index', () => ({
    request: jest.fn(async (_method: string, host: string, port: number, path: string, body: string) => {
        const route = path.split('?')[0];
        mockCaptured.push({ host, port, path, route, body: JSON.parse(body) });
        const resp = mockResponses[route];
        if (!resp) throw new Error(`No mock for ${route}`);
        return { status: 200, body: JSON.stringify(resp) };
    }),
}));
jest.mock('../../modules/native-keys/src/index', () => ({
    generateKey: jest.fn(async (alias: string) => ({ publicKey: FAKE_PUB_KEY_B64URL, keyAlias: alias })),
    sign: jest.fn(async () => ({ signature: FAKE_SIGNATURE_B64URL })),
}));

import { sha256 } from '@noble/hashes/sha2.js';

import * as NativeKeys from '../../modules/native-keys/src/index';
import * as NativeRaTls from '../../modules/native-ratls/src/index';
import * as fido2 from '../services/fido2';

// ── Helpers ─────────────────────────────────────────────────────────────

function base64urlDecode(str: string): Uint8Array {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function isValidBase64url(str: string): boolean {
    return /^[A-Za-z0-9_-]+$/.test(str);
}

const sent = (route: string) => mockCaptured.find((r) => r.route === route)!;

const REG_CHALLENGE = 'dGVzdC1jaGFsbGVuZ2UtMTIzNDU2Nzg5MA';
const AUTH_CHALLENGE = 'YXV0aC1jaGFsbGVuZ2UtOTg3NjU0MzIxMA';

beforeEach(() => {
    mockCaptured.length = 0;
    jest.clearAllMocks();
    mockResponses['/fido2/register/begin'] = {
        publicKey: {
            challenge: REG_CHALLENGE,
            rp: { id: 'example.privasys.org', name: 'Example App' },
            user: { id: 'dXNlcjEyMw', name: 'test-key', displayName: 'test-key' },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
    };
    mockResponses['/fido2/register/complete'] = {
        status: 'ok',
        sessionToken: 'reg-session-token',
        userId: 'user-id-from-idp',
    };
    mockResponses['/fido2/authenticate/begin'] = {
        publicKey: { challenge: AUTH_CHALLENGE, rpId: 'example.privasys.org' },
    };
    mockResponses['/fido2/authenticate/complete'] = {
        status: 'ok',
        sessionToken: 'auth-session-token',
        userId: 'user-id-from-idp',
    };
});

// ── Registration ────────────────────────────────────────────────────────

describe('fido2.register', () => {
    const ORIGIN = 'example.privasys.org:8443';
    const KEY_ALIAS = 'fido2-example.privasys.org';
    const SESSION_ID = 'browser-session-abc123';

    it('completes without crypto.subtle', async () => {
        const originalSubtle = globalThis.crypto?.subtle;
        if (globalThis.crypto) {
            Object.defineProperty(globalThis.crypto, 'subtle', { value: undefined, configurable: true });
        }
        try {
            const result = await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
            expect(result.sessionToken).toBe('reg-session-token');
            expect(result.credentialId).toBeTruthy();
        } finally {
            if (globalThis.crypto && originalSubtle) {
                Object.defineProperty(globalThis.crypto, 'subtle', { value: originalSubtle, configurable: true });
            }
        }
    });

    it('sends the browser session on the path and a random handle by default', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        const begin = sent('/fido2/register/begin');
        expect(begin.path).toBe(`/fido2/register/begin?session_id=${SESSION_ID}`);
        // No display name given: the key alias stands in.
        expect(begin.body.userName).toBe(KEY_ALIAS);
        expect(begin.body.userHandle).toMatch(/^[A-Za-z0-9_-]{43}$/);
    });

    it('sends the given identity handle, and asks for no server phrase when told to', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID, 'Alice', 'derived-handle', undefined, { clientPhrase: true });
        const begin = sent('/fido2/register/begin');
        expect(begin.body).toEqual({ userName: 'Alice', userHandle: 'derived-handle' });
        expect(begin.path).toContain('&client_phrase=1');
    });

    it('does not ask about the phrase unless told to', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID, 'Alice', 'h');
        expect(sent('/fido2/register/begin').path).not.toContain('client_phrase');
    });

    it('sends a standard WebAuthn attestation response', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        const complete = sent('/fido2/register/complete');
        expect(complete.path).toBe(`/fido2/register/complete?challenge=${REG_CHALLENGE}`);
        expect(complete.body.type).toBe('public-key');
        expect(complete.body.id).toBe(complete.body.rawId);
        expect(isValidBase64url(complete.body.id)).toBe(true);
        expect(isValidBase64url(complete.body.response.clientDataJSON)).toBe(true);
        expect(isValidBase64url(complete.body.response.attestationObject)).toBe(true);
    });

    it('builds valid clientDataJSON for registration', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        const cdj = JSON.parse(
            new TextDecoder().decode(base64urlDecode(sent('/fido2/register/complete').body.response.clientDataJSON)),
        );
        expect(cdj).toEqual({
            type: 'webauthn.create',
            challenge: REG_CHALLENGE,
            origin: `https://${ORIGIN}`,
            crossOrigin: false,
        });
    });

    it('builds a CBOR attestation object with fmt "none"', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        const attObj = base64urlDecode(sent('/fido2/register/complete').body.response.attestationObject);
        expect(attObj[0]).toBe(0xa3); // map(3)
        expect(attObj[1]).toBe(0x63); // text(3)
        expect(String.fromCharCode(attObj[2], attObj[3], attObj[4])).toBe('fmt');
        expect(attObj[5]).toBe(0x64); // text(4)
        expect(String.fromCharCode(attObj[6], attObj[7], attObj[8], attObj[9])).toBe('none');
    });

    it('builds authenticatorData with UP, UV and AT set and a zero counter', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        const attObj = base64urlDecode(sent('/fido2/register/complete').body.response.attestationObject);
        const { start } = authDataOf(attObj);
        expect(Buffer.from(attObj.slice(start, start + 32))).toEqual(
            Buffer.from(sha256(new TextEncoder().encode('example.privasys.org'))),
        );
        expect(attObj[start + 32]).toBe(0x45); // UP | UV | AT
        expect(Array.from(attObj.slice(start + 33, start + 37))).toEqual([0, 0, 0, 0]);
    });

    it('derives the credential id from the public key', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        const credIdBytes = base64urlDecode(sent('/fido2/register/complete').body.id);
        expect(Buffer.from(credIdBytes)).toEqual(Buffer.from(sha256(base64urlDecode(FAKE_PUB_KEY_B64URL))));
    });

    it('generates a biometric-gated key under the alias and signs with it', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        expect(NativeKeys.generateKey).toHaveBeenCalledWith(KEY_ALIAS, true);
        expect(NativeKeys.sign).toHaveBeenCalledWith(KEY_ALIAS, expect.any(String));
    });

    it('returns the session, the credential and the IdP user id', async () => {
        const result = await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        expect(result).toMatchObject({
            sessionToken: 'reg-session-token',
            userHandle: 'dXNlcjEyMw',
            userName: 'test-key',
            serverRpId: 'example.privasys.org',
            userId: 'user-id-from-idp',
        });
    });
});

// ── Authentication ──────────────────────────────────────────────────────

describe('fido2.authenticate', () => {
    const ORIGIN = 'example.privasys.org:8443';
    const KEY_ALIAS = 'fido2-example.privasys.org';
    const CRED_ID = 'dGVzdC1jcmVkLWlk';
    const SESSION_ID = 'browser-session-xyz789';

    it('sends the credential to begin and a standard assertion to complete', async () => {
        await fido2.authenticate(ORIGIN, KEY_ALIAS, CRED_ID, SESSION_ID);
        const begin = sent('/fido2/authenticate/begin');
        expect(begin.path).toBe(`/fido2/authenticate/begin?session_id=${SESSION_ID}`);
        expect(begin.body).toEqual({ credentialId: CRED_ID });

        const complete = sent('/fido2/authenticate/complete');
        expect(complete.path).toBe(`/fido2/authenticate/complete?challenge=${AUTH_CHALLENGE}`);
        expect(complete.body.id).toBe(CRED_ID);
        expect(complete.body.response.signature).toBe(FAKE_SIGNATURE_B64URL);
        expect(isValidBase64url(complete.body.response.clientDataJSON)).toBe(true);
    });

    it('builds valid clientDataJSON for authentication', async () => {
        await fido2.authenticate(ORIGIN, KEY_ALIAS, CRED_ID, SESSION_ID);
        const cdj = JSON.parse(
            new TextDecoder().decode(base64urlDecode(sent('/fido2/authenticate/complete').body.response.clientDataJSON)),
        );
        expect(cdj.type).toBe('webauthn.get');
        expect(cdj.challenge).toBe(AUTH_CHALLENGE);
        expect(cdj.origin).toBe(`https://${ORIGIN}`);
    });

    it('builds authenticatorData with UP and UV and no attested data', async () => {
        await fido2.authenticate(ORIGIN, KEY_ALIAS, CRED_ID, SESSION_ID, 'example.privasys.org');
        const authData = base64urlDecode(sent('/fido2/authenticate/complete').body.response.authenticatorData);
        expect(authData.length).toBe(37); // rpIdHash(32) + flags(1) + signCount(4)
        expect(authData[32]).toBe(0x05); // UP | UV
    });

    it('returns the session and the IdP user id', async () => {
        const result = await fido2.authenticate(ORIGIN, KEY_ALIAS, CRED_ID, SESSION_ID);
        expect(result.sessionToken).toBe('auth-session-token');
        expect(result.userId).toBe('user-id-from-idp');
    });
});

// ── Transport ───────────────────────────────────────────────────────────

describe('transport', () => {
    it('makes two calls per ceremony, to the origin host and port', async () => {
        await fido2.register('myapp.privasys.org:8446', 'key', 'sess');
        expect(NativeRaTls.request).toHaveBeenCalledTimes(2);
        expect(NativeRaTls.request).toHaveBeenCalledWith(
            'POST',
            'myapp.privasys.org',
            8446,
            '/fido2/register/begin?session_id=sess',
            expect.any(String),
            undefined,
            undefined,
            { attestation: 'none', trust: 'public' },
        );
    });
});

// ── AAGUID ──────────────────────────────────────────────────────────────

describe('AAGUID in attestation object', () => {
    it('embeds the Privasys Wallet AAGUID, then a 32-byte credential id', async () => {
        await fido2.register('example.privasys.org:8443', 'k', 'sess');
        const attObj = base64urlDecode(sent('/fido2/register/complete').body.response.attestationObject);
        const { start } = authDataOf(attObj);
        const aaguid = Array.from(attObj.slice(start + 37, start + 53))
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('');
        expect(aaguid).toBe('f47ac10b58cc4372a5670e02b2c3d479');
        expect((attObj[start + 53] << 8) | attObj[start + 54]).toBe(32);
    });
});

// ── CBOR helpers ────────────────────────────────────────────────────────

/** Locate the authData byte string after the "authData" key. */
function authDataOf(attObj: Uint8Array): { start: number; length: number } {
    const keyOffset = findCborText(attObj, 'authData');
    if (keyOffset < 0) throw new Error('no authData key');
    return parseCborBstrHeader(attObj, keyOffset + 1 + 8);
}

/** Find the offset of a CBOR text string key in a buffer. */
function findCborText(buf: Uint8Array, text: string): number {
    const textBytes = new TextEncoder().encode(text);
    for (let i = 0; i < buf.length - textBytes.length; i++) {
        let match = true;
        for (let j = 0; j < textBytes.length; j++) {
            if (buf[i + 1 + j] !== textBytes[j]) {
                match = false;
                break;
            }
        }
        if (match && (buf[i] & 0xe0) === 0x60) return i;
    }
    return -1;
}

/** Parse a CBOR bstr header and return {start, length} of the byte data. */
function parseCborBstrHeader(buf: Uint8Array, offset: number): { start: number; length: number } {
    const additionalInfo = buf[offset] & 0x1f;
    if (additionalInfo < 24) return { start: offset + 1, length: additionalInfo };
    if (additionalInfo === 24) return { start: offset + 2, length: buf[offset + 1] };
    if (additionalInfo === 25) return { start: offset + 3, length: (buf[offset + 1] << 8) | buf[offset + 2] };
    throw new Error(`Unsupported CBOR bstr length at offset ${offset}`);
}
