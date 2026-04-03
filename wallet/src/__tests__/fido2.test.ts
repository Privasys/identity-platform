/**
 * FIDO2 service unit tests.
 *
 * Mocks native modules (NativeRaTls, NativeKeys) and validates that the
 * FIDO2 registration and authentication ceremonies produce correct
 * WebAuthn-compliant wire messages for the enclave.
 *
 * These tests catch:
 *  - crypto.subtle usage (unavailable in React Native)
 *  - Wrong wire format (envelope vs serde-tag)
 *  - Base64url encoding errors
 *  - CBOR/attestation object structure issues
 *  - Missing or extra fields in enclave requests
 */

// ── Polyfill globals that exist in React Native but not in Node ─────────
// Node 20+ has crypto.getRandomValues natively, no polyfill needed.
// @ts-expect-error -- __DEV__ is set by React Native runtime
globalThis.__DEV__ = true;

// ── Mock native modules BEFORE importing fido2 ─────────────────────────
// Fake P-256 uncompressed public key (65 bytes: 0x04 || x || y)
const FAKE_PUB_KEY_B64URL =
    'BFqR7zQvBgrYjqGOcnqHJbquGFhdOvEyLMOcEMtzmEiQPQR3bwC3EKw2TdSNJrVWBTMbr_UDfj8r0lic0wu7Lg';
const FAKE_SIGNATURE_B64URL = 'MEUCIQC1234fakesignatureAIBcde567890';

const mockPostResponses: Record<string, object> = {};
const mockCapturedRequests: Array<{ path: string; body: any }> = [];

jest.mock('../../modules/native-ratls/src/index', () => ({
    post: jest.fn(async (_host: string, _port: number, path: string, body: string) => {
        const parsed = JSON.parse(body);
        mockCapturedRequests.push({ path, body: parsed });

        const resp = mockPostResponses[path];
        if (!resp) throw new Error(`No mock for ${path}`);
        return { status: 200, body: JSON.stringify(resp) };
    }),
}));

jest.mock('../../modules/native-keys/src/index', () => ({
    generateKey: jest.fn(async (_alias: string, _requireAuth: boolean) => ({
        publicKey: 'BFqR7zQvBgrYjqGOcnqHJbquGFhdOvEyLMOcEMtzmEiQPQR3bwC3EKw2TdSNJrVWBTMbr_UDfj8r0lic0wu7Lg',
        keyAlias: _alias,
    })),
    sign: jest.fn(async (_alias: string, _data: string) => ({
        signature: 'MEUCIQC1234fakesignatureAIBcde567890',
    })),
}));

// Track requests sent to the enclave
let capturedRequests: Array<{ path: string; body: any }> = [];

// Import AFTER mocks are set up
import * as fido2 from '../services/fido2';
import * as NativeRaTls from '../../modules/native-ratls/src/index';
import * as NativeKeys from '../../modules/native-keys/src/index';
import { sha256 } from '@noble/hashes/sha2';

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

// ── Setup / Teardown ────────────────────────────────────────────────────

beforeEach(() => {
    capturedRequests = [];
    mockCapturedRequests.length = 0;
    jest.clearAllMocks();

    // Default mock responses
    mockPostResponses['/fido2/register/begin'] = {
        type: 'register_options',
        challenge: 'dGVzdC1jaGFsbGVuZ2UtMTIzNDU2Nzg5MA',
        rp: { id: 'example.privasys.org', name: 'Example App' },
        user: { id: 'dXNlcjEyMw', name: 'test-key', display_name: 'test-key' },
        pub_key_cred_params: [{ type: 'public-key', alg: -7 }],
        authenticator_selection: {
            authenticator_attachment: 'platform',
            resident_key: 'required',
            user_verification: 'required',
        },
        attestation: 'direct',
    };

    mockPostResponses['/fido2/register/complete'] = {
        type: 'register_ok',
        status: 'ok',
        session_token: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    };

    mockPostResponses['/fido2/authenticate/begin'] = {
        type: 'authenticate_options',
        challenge: 'YXV0aC1jaGFsbGVuZ2UtOTg3NjU0MzIxMA',
        allow_credentials: [{ type: 'public-key', id: 'test-cred-id' }],
        user_verification: 'required',
    };

    mockPostResponses['/fido2/authenticate/complete'] = {
        type: 'authenticate_ok',
        status: 'ok',
        session_token: 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
    };
});

// ── Registration Tests ──────────────────────────────────────────────────

describe('fido2.register', () => {
    const ORIGIN = 'example.privasys.org:8443';
    const KEY_ALIAS = 'fido2-example.privasys.org';
    const SESSION_ID = 'browser-session-abc123';

    it('completes without crypto.subtle', async () => {
        // Temporarily remove crypto.subtle to simulate React Native
        const originalSubtle = globalThis.crypto?.subtle;
        if (globalThis.crypto) {
            Object.defineProperty(globalThis.crypto, 'subtle', { value: undefined, configurable: true });
        }
        try {
            const result = await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
            expect(result.sessionToken).toBeTruthy();
            expect(result.credentialId).toBeTruthy();
        } finally {
            if (globalThis.crypto && originalSubtle) {
                Object.defineProperty(globalThis.crypto, 'subtle', { value: originalSubtle, configurable: true });
            }
        }
    });

    it('sends register_begin with serde tag format', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        capturedRequests = [...mockCapturedRequests];

        const beginReq = capturedRequests.find(r => r.path === '/fido2/register/begin');
        expect(beginReq).toBeDefined();
        expect(beginReq!.body).toMatchObject({
            type: 'register_begin',
            user_name: KEY_ALIAS,
            browser_session_id: SESSION_ID,
        });
        // Must have user_handle (base64url-encoded random bytes)
        expect(beginReq!.body.user_handle).toBeDefined();
        expect(isValidBase64url(beginReq!.body.user_handle)).toBe(true);
    });

    it('sends register_complete with all required fields', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        capturedRequests = [...mockCapturedRequests];

        const completeReq = capturedRequests.find(r => r.path === '/fido2/register/complete');
        expect(completeReq).toBeDefined();

        const body = completeReq!.body;
        expect(body.type).toBe('register_complete');
        expect(body.challenge).toBe('dGVzdC1jaGFsbGVuZ2UtMTIzNDU2Nzg5MA');
        expect(body.browser_session_id).toBe(SESSION_ID);

        // All base64url-encoded fields must be valid
        expect(isValidBase64url(body.credential_id)).toBe(true);
        expect(isValidBase64url(body.client_data_json)).toBe(true);
        expect(isValidBase64url(body.attestation_object)).toBe(true);
    });

    it('builds valid clientDataJSON for registration', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        capturedRequests = [...mockCapturedRequests];

        const completeReq = capturedRequests.find(r => r.path === '/fido2/register/complete')!;
        const cdj = JSON.parse(
            new TextDecoder().decode(base64urlDecode(completeReq.body.client_data_json))
        );

        expect(cdj.type).toBe('webauthn.create');
        expect(cdj.challenge).toBe('dGVzdC1jaGFsbGVuZ2UtMTIzNDU2Nzg5MA');
        expect(cdj.origin).toBe(`https://${ORIGIN}`);
        expect(cdj.crossOrigin).toBe(false);
    });

    it('builds valid attestation object CBOR', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        capturedRequests = [...mockCapturedRequests];

        const completeReq = capturedRequests.find(r => r.path === '/fido2/register/complete')!;
        const attObj = base64urlDecode(completeReq.body.attestation_object);

        // CBOR map(3) header
        expect(attObj[0]).toBe(0xa3);
        // First key: "fmt" (text(3))
        expect(attObj[1]).toBe(0x63); // text(3)
        // "fmt" bytes
        expect(String.fromCharCode(attObj[2], attObj[3], attObj[4])).toBe('fmt');
        // Value: "none" (text(4))
        expect(attObj[5]).toBe(0x64); // text(4)
        expect(String.fromCharCode(attObj[6], attObj[7], attObj[8], attObj[9])).toBe('none');
    });

    it('builds authenticatorData with correct structure', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        capturedRequests = [...mockCapturedRequests];

        const completeReq = capturedRequests.find(r => r.path === '/fido2/register/complete')!;
        const attObj = base64urlDecode(completeReq.body.attestation_object);

        // Find authData in CBOR — it follows the "authData" key and bstr length prefix
        // The authData starts after: map(3) + "fmt"+"none" + "attStmt"+map(0) + "authData"+bstrLen
        // = 1 + (1+3) + (1+4) + (1+7) + (1+0) + (1+8) + bstr_header bytes
        // authData structure: rpIdHash(32) + flags(1) + signCount(4) + attestedCredData(...)
        // flags should be 0x45 = UP|UV|AT

        // Find the authData bstr by scanning for "authData" text in CBOR
        const authDataKeyOffset = findCborText(attObj, 'authData');
        expect(authDataKeyOffset).toBeGreaterThan(0);

        // After the key text, the bstr header tells us the authData length
        const bstrOffset = authDataKeyOffset + 1 + 8; // text(8) + "authData"
        const authDataOffset = parseCborBstrHeader(attObj, bstrOffset);
        expect(authDataOffset.start).toBeGreaterThan(0);

        // rpIdHash is 32 bytes
        const flags = attObj[authDataOffset.start + 32];
        expect(flags).toBe(0x45); // UP | UV | AT

        // signCount is next 4 bytes (should be 0)
        const signCount = (attObj[authDataOffset.start + 33] << 24) |
            (attObj[authDataOffset.start + 34] << 16) |
            (attObj[authDataOffset.start + 35] << 8) |
            attObj[authDataOffset.start + 36];
        expect(signCount).toBe(0);
    });

    it('credential ID is SHA-256 of public key', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        capturedRequests = [...mockCapturedRequests];

        const completeReq = capturedRequests.find(r => r.path === '/fido2/register/complete')!;
        const credIdBytes = base64urlDecode(completeReq.body.credential_id);

        // Credential ID should be SHA-256(publicKey)
        const pubKeyBytes = base64urlDecode(FAKE_PUB_KEY_B64URL);
        const expected = sha256(pubKeyBytes);
        expect(Buffer.from(credIdBytes)).toEqual(Buffer.from(expected));
    });

    it('calls NativeKeys.generateKey with correct alias', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        expect(NativeKeys.generateKey).toHaveBeenCalledWith(KEY_ALIAS, true);
    });

    it('calls NativeKeys.sign with data to sign', async () => {
        await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        expect(NativeKeys.sign).toHaveBeenCalledWith(KEY_ALIAS, expect.any(String));
    });

    it('returns session token and credential from enclave response', async () => {
        const result = await fido2.register(ORIGIN, KEY_ALIAS, SESSION_ID);
        expect(result.sessionToken).toBe(
            'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
        );
        expect(result.credentialId).toBeTruthy();
        expect(result.userHandle).toBe('dXNlcjEyMw');
        expect(result.userName).toBe('test-key');
    });
});

// ── Authentication Tests ────────────────────────────────────────────────

describe('fido2.authenticate', () => {
    const ORIGIN = 'example.privasys.org:8443';
    const KEY_ALIAS = 'fido2-example.privasys.org';
    const CRED_ID = 'dGVzdC1jcmVkLWlk';
    const SESSION_ID = 'browser-session-xyz789';

    it('completes without crypto.subtle', async () => {
        const originalSubtle = globalThis.crypto?.subtle;
        if (globalThis.crypto) {
            Object.defineProperty(globalThis.crypto, 'subtle', { value: undefined, configurable: true });
        }
        try {
            const result = await fido2.authenticate(ORIGIN, KEY_ALIAS, CRED_ID, SESSION_ID);
            expect(result.sessionToken).toBeTruthy();
        } finally {
            if (globalThis.crypto && originalSubtle) {
                Object.defineProperty(globalThis.crypto, 'subtle', { value: originalSubtle, configurable: true });
            }
        }
    });

    it('sends authenticate_begin with serde tag format', async () => {
        await fido2.authenticate(ORIGIN, KEY_ALIAS, CRED_ID, SESSION_ID);
        capturedRequests = [...mockCapturedRequests];

        const beginReq = capturedRequests.find(r => r.path === '/fido2/authenticate/begin');
        expect(beginReq).toBeDefined();
        expect(beginReq!.body).toEqual({
            type: 'authenticate_begin',
            credential_id: CRED_ID,
            browser_session_id: SESSION_ID,
        });
    });

    it('sends authenticate_complete with all required fields', async () => {
        await fido2.authenticate(ORIGIN, KEY_ALIAS, CRED_ID, SESSION_ID);
        capturedRequests = [...mockCapturedRequests];

        const completeReq = capturedRequests.find(
            r => r.path === '/fido2/authenticate/complete'
        );
        expect(completeReq).toBeDefined();

        const body = completeReq!.body;
        expect(body.type).toBe('authenticate_complete');
        expect(body.challenge).toBe('YXV0aC1jaGFsbGVuZ2UtOTg3NjU0MzIxMA');
        expect(body.credential_id).toBe(CRED_ID);
        expect(body.browser_session_id).toBe(SESSION_ID);

        expect(isValidBase64url(body.client_data_json)).toBe(true);
        expect(isValidBase64url(body.authenticator_data)).toBe(true);
        expect(body.signature).toBe(FAKE_SIGNATURE_B64URL);
    });

    it('builds valid clientDataJSON for authentication', async () => {
        await fido2.authenticate(ORIGIN, KEY_ALIAS, CRED_ID, SESSION_ID);
        capturedRequests = [...mockCapturedRequests];

        const completeReq = capturedRequests.find(
            r => r.path === '/fido2/authenticate/complete'
        )!;
        const cdj = JSON.parse(
            new TextDecoder().decode(base64urlDecode(completeReq.body.client_data_json))
        );

        expect(cdj.type).toBe('webauthn.get');
        expect(cdj.challenge).toBe('YXV0aC1jaGFsbGVuZ2UtOTg3NjU0MzIxMA');
        expect(cdj.origin).toBe(`https://${ORIGIN}`);
        expect(cdj.crossOrigin).toBe(false);
    });

    it('builds authenticatorData with correct flags for assertion', async () => {
        await fido2.authenticate(ORIGIN, KEY_ALIAS, CRED_ID, SESSION_ID);
        capturedRequests = [...mockCapturedRequests];

        const completeReq = capturedRequests.find(
            r => r.path === '/fido2/authenticate/complete'
        )!;
        const authData = base64urlDecode(completeReq.body.authenticator_data);

        // rpIdHash(32) + flags(1) + signCount(4) = 37 bytes
        expect(authData.length).toBe(37);

        // flags = 0x05 = UP | UV (no AT flag for assertion)
        expect(authData[32]).toBe(0x05);

        // signCount = 1 (incremented from registration)
        const signCount = (authData[33] << 24) | (authData[34] << 16) |
            (authData[35] << 8) | authData[36];
        expect(signCount).toBe(1);
    });

    it('returns session token from enclave response', async () => {
        const result = await fido2.authenticate(ORIGIN, KEY_ALIAS, CRED_ID, SESSION_ID);
        expect(result.sessionToken).toBe(
            'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321'
        );
    });
});

// ── Wire Format Regression Tests ────────────────────────────────────────

describe('wire format', () => {
    it('never sends envelope-style requests', async () => {
        await fido2.register('host:443', 'key', 'sess');
        capturedRequests = [...mockCapturedRequests];

        for (const req of capturedRequests) {
            // Envelope style would have fields like "register_begin", "register_complete"
            expect(req.body).not.toHaveProperty('register_begin');
            expect(req.body).not.toHaveProperty('register_complete');
            expect(req.body).not.toHaveProperty('authenticate_begin');
            expect(req.body).not.toHaveProperty('authenticate_complete');
            // All requests must use serde tag format
            expect(req.body.type).toBeDefined();
        }
    });

    it('makes exactly 2 RA-TLS calls per registration', async () => {
        await fido2.register('host:443', 'key', 'sess');
        expect(NativeRaTls.post).toHaveBeenCalledTimes(2);
    });

    it('makes exactly 2 RA-TLS calls per authentication', async () => {
        await fido2.authenticate('host:443', 'key', 'cred', 'sess');
        expect(NativeRaTls.post).toHaveBeenCalledTimes(2);
    });

    it('passes correct host and port from origin', async () => {
        await fido2.register('myapp.privasys.org:8446', 'key', 'sess');

        expect(NativeRaTls.post).toHaveBeenCalledWith(
            'myapp.privasys.org',
            8446,
            '/fido2/register/begin',
            expect.any(String),
        );
    });
});

// ── CBOR Helpers ────────────────────────────────────────────────────────

/** Find the offset of a CBOR text string key in a buffer. */
function findCborText(buf: Uint8Array, text: string): number {
    const textBytes = new TextEncoder().encode(text);
    for (let i = 0; i < buf.length - textBytes.length; i++) {
        let match = true;
        for (let j = 0; j < textBytes.length; j++) {
            if (buf[i + 1 + j] !== textBytes[j]) { match = false; break; }
        }
        if (match && (buf[i] & 0xe0) === 0x60) { // major type 3 (text string)
            return i;
        }
    }
    return -1;
}

/** Parse a CBOR bstr header and return {start, length} of the byte data. */
function parseCborBstrHeader(buf: Uint8Array, offset: number): { start: number; length: number } {
    const initial = buf[offset];
    const additionalInfo = initial & 0x1f;
    if (additionalInfo < 24) {
        return { start: offset + 1, length: additionalInfo };
    } else if (additionalInfo === 24) {
        return { start: offset + 2, length: buf[offset + 1] };
    } else if (additionalInfo === 25) {
        return { start: offset + 3, length: (buf[offset + 1] << 8) | buf[offset + 2] };
    }
    throw new Error(`Unsupported CBOR bstr length at offset ${offset}`);
}
