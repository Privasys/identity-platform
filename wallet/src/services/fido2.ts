// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * FIDO2 client-side operations.
 *
 * Handles the WebAuthn registration and authentication ceremonies by
 * communicating with the enclave's FIDO2 endpoints over HTTPS
 * (the RA-TLS connection is already established at this point).
 */

import { sha256 } from '@noble/hashes/sha2';

import * as NativeKeys from '../../modules/native-keys/src/index';
import * as NativeRaTls from '../../modules/native-ratls/src/index';

// ── Wire types matching the enclave's Fido2Request/Fido2Response ────────
// Enclave uses serde(tag = "type") — responses are flat with a `type` field.

interface RegisterBeginResponse {
    type: 'register_options';
    challenge: string;
    rp: { id: string; name: string };
    user: { id: string; name: string; display_name: string };
    pub_key_cred_params: Array<{ type: string; alg: number }>;
    authenticator_selection: {
        authenticator_attachment: string;
        user_verification: string;
    };
    attestation: string;
}

interface RegisterCompleteResponse {
    type: 'register_ok';
    status: string;
    session_token?: string;
}

interface AuthenticateBeginResponse {
    type: 'authenticate_options';
    challenge: string;
    allow_credentials?: Array<{ type: string; id: string }>;
    user_verification: string;
}

interface AuthenticateCompleteResponse {
    type: 'authenticate_ok';
    status: string;
    session_token?: string;
}

interface Fido2Error {
    type: 'error';
    error: string;
}

type Fido2Response<T> = T | Fido2Error;

// ── Helpers ─────────────────────────────────────────────────────────────

function base64urlEncode(data: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < data.length; i++) {
        binary += String.fromCharCode(data[i]!);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str: string): Uint8Array {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

async function fido2Fetch<T extends object>(origin: string, path: string, body?: object): Promise<T> {
    const url = new URL(`https://${origin}`);
    const host = url.hostname;
    const port = parseInt(url.port || '443', 10);

    console.log(`[FIDO2] fetch ${path} → ${host}:${port}`);
    if (body) console.log(`[FIDO2] request body: ${JSON.stringify(body).substring(0, 300)}`);

    let result;
    try {
        result = await NativeRaTls.post(
            host,
            port,
            path,
            body ? JSON.stringify(body) : '{}',
        );
    } catch (e: any) {
        console.error(`[FIDO2] ${path} — NativeRaTls.post threw: ${e.message}`, e);
        throw e;
    }

    console.log(`[FIDO2] ${path} — status=${result.status}, body=${result.body.substring(0, 300)}`);

    if (result.status < 200 || result.status >= 300) {
        throw new Error(`FIDO2 request failed: ${result.status} — ${result.body.substring(0, 200)}`);
    }

    const json: Fido2Response<T> = JSON.parse(result.body);
    if ('type' in json && (json as any).type === 'error') {
        const msg = (json as Fido2Error).error;
        console.error(`[FIDO2] ${path} — enclave error: ${msg}`);
        throw new Error(`FIDO2 error: ${msg}`);
    }
    return json as T;
}

// ── CBOR encoding (minimal, for WebAuthn attestation objects) ───────────

/**
 * Build the attestation object CBOR for fmt="none".
 * Structure: { "fmt": "none", "attStmt": {}, "authData": <bytes> }
 */
function buildAttestationObject(authData: Uint8Array): Uint8Array {
    const parts: number[] = [];

    // Map(3)
    parts.push(0xa3);

    // "fmt" => "none"
    // key: text(3) "fmt"
    parts.push(0x63, 0x66, 0x6d, 0x74);
    // value: text(4) "none"
    parts.push(0x64, 0x6e, 0x6f, 0x6e, 0x65);

    // "attStmt" => {} (empty map, NOT a byte string)
    // key: text(7) "attStmt"
    parts.push(0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74);
    // value: map(0)
    parts.push(0xa0);

    // "authData" => bstr
    // key: text(8) "authData"
    parts.push(0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61);
    // value: bstr(authData.length)
    if (authData.length < 24) {
        parts.push(0x40 | authData.length);
    } else if (authData.length < 256) {
        parts.push(0x58, authData.length);
    } else {
        parts.push(0x59, (authData.length >> 8) & 0xff, authData.length & 0xff);
    }

    const header = new Uint8Array(parts);
    return concat([header, authData]);
}

// ── AAGUID for Privasys Wallet ──────────────────────────────────────────

// A unique AAGUID identifying the Privasys Wallet authenticator.
// Generated: f47ac10b-58cc-4372-a567-0e02b2c3d479
const PRIVASYS_WALLET_AAGUID = new Uint8Array([
    0xf4, 0x7a, 0xc1, 0x0b, 0x58, 0xcc, 0x43, 0x72, 0xa5, 0x67, 0x0e, 0x02, 0xb2, 0xc3, 0xd4,
    0x79
]);

// ── Public API ──────────────────────────────────────────────────────────

/**
 * Register a new FIDO2 credential with an enclave.
 *
 * @param origin  The enclave's origin (hostname:port).
 * @param keyAlias  The hardware key alias to use (from native-keys).
 * @param browserSessionId  Session ID to relay the session token to the browser.
 * @returns The session token for the browser and the credential ID.
 */
export async function register(
    origin: string,
    keyAlias: string,
    browserSessionId: string
): Promise<{ sessionToken: string; credentialId: string; userHandle: string; userName: string }> {
    // 1. Begin registration — get challenge and options from enclave
    //    Generate a random user handle (64 random bytes, base64url-encoded)
    const userHandleBytes = new Uint8Array(32);
    crypto.getRandomValues(userHandleBytes);
    const userHandle = base64urlEncode(userHandleBytes);

    const beginResp = await fido2Fetch<RegisterBeginResponse>(
        origin,
        '/fido2/register/begin',
        {
            type: 'register_begin',
            user_name: keyAlias,
            user_handle: userHandle,
            browser_session_id: browserSessionId,
        }
    );
    const options = beginResp;

    // 2. Generate or retrieve hardware key
    const keyInfo = await NativeKeys.generateKey(keyAlias, true);

    // 3. Build clientDataJSON
    const clientData = JSON.stringify({
        type: 'webauthn.create',
        challenge: options.challenge,
        origin: `https://${origin}`,
        crossOrigin: false
    });
    const clientDataBytes = new TextEncoder().encode(clientData);
    const clientDataB64 = base64urlEncode(clientDataBytes);

    // 4. Build authenticatorData
    //    rpIdHash (32) + flags (1) + signCount (4) + attestedCredentialData
    const rpIdHash = sha256(new TextEncoder().encode(options.rp.id));

    // Credential ID from the public key (hash of public key)
    const pubKeyBytes = base64urlDecode(keyInfo.publicKey);
    const credentialIdBytes = sha256(pubKeyBytes);

    // COSE Key encoding for P-256 (ES256)
    // {1: 2, 3: -7, -1: 1, -2: x, -3: y}
    const x = pubKeyBytes.slice(1, 33);
    const y = pubKeyBytes.slice(33, 65);
    const coseKey = buildCoseKey(x, y);

    // attestedCredentialData: AAGUID (16) + credIdLen (2) + credentialId + coseKey
    const credIdLen = new Uint8Array(2);
    credIdLen[0] = (credentialIdBytes.length >> 8) & 0xff;
    credIdLen[1] = credentialIdBytes.length & 0xff;

    const attestedCredData = concat([
        PRIVASYS_WALLET_AAGUID,
        credIdLen,
        credentialIdBytes,
        coseKey
    ]);

    // Flags: UP (0x01) | UV (0x04) | AT (0x40) = 0x45
    const flags = new Uint8Array([0x45]);
    const signCount = new Uint8Array([0, 0, 0, 0]); // Initial sign count

    const authData = concat([rpIdHash, flags, signCount, attestedCredData]);

    // 5. Sign: authData || SHA-256(clientDataJSON) per WebAuthn spec
    const clientDataHash = sha256(clientDataBytes);
    const signedData = concat([authData, clientDataHash]);
    const signedDataB64 = base64urlEncode(signedData);
    const sigResult = await NativeKeys.sign(keyAlias, signedDataB64);

    // 6. Build attestation object CBOR: { "fmt": "none", "attStmt": {}, "authData": <bytes> }
    const attestationObject = buildAttestationObject(authData);

    // 7. Complete registration
    const completeResp = await fido2Fetch<RegisterCompleteResponse>(
        origin,
        '/fido2/register/complete',
        {
            type: 'register_complete',
            challenge: options.challenge,
            credential_id: base64urlEncode(credentialIdBytes),
            client_data_json: clientDataB64,
            attestation_object: base64urlEncode(attestationObject),
            browser_session_id: browserSessionId,
        }
    );

    return {
        sessionToken: completeResp.session_token || '',
        credentialId: base64urlEncode(credentialIdBytes),
        userHandle: options.user.id,
        userName: options.user.name
    };
}

/**
 * Authenticate with an existing FIDO2 credential.
 *
 * @param origin  The enclave's origin (hostname:port).
 * @param keyAlias  The hardware key alias.
 * @param credentialId  The credential ID to authenticate with.
 * @param browserSessionId  Session ID to relay the session token to the browser.
 * @returns The session token for the browser.
 */
export async function authenticate(
    origin: string,
    keyAlias: string,
    credentialId: string,
    browserSessionId: string
): Promise<{ sessionToken: string }> {
    // 1. Begin authentication
    const beginResp = await fido2Fetch<AuthenticateBeginResponse>(
        origin,
        '/fido2/authenticate/begin',
        {
            type: 'authenticate_begin',
            credential_id: credentialId,
            browser_session_id: browserSessionId,
        }
    );
    const options = beginResp;

    // 2. Build clientDataJSON
    const clientData = JSON.stringify({
        type: 'webauthn.get',
        challenge: options.challenge,
        origin: `https://${origin}`,
        crossOrigin: false
    });
    const clientDataBytes = new TextEncoder().encode(clientData);
    const clientDataB64 = base64urlEncode(clientDataBytes);

    // 3. Build authenticatorData (simpler — no attested credential data)
    const rpIdHash = sha256(new TextEncoder().encode(origin.split(':')[0]));
    const flags = new Uint8Array([0x05]); // UP | UV
    const signCount = new Uint8Array([0, 0, 0, 1]); // Incremented

    const authData = concat([rpIdHash, flags, signCount]);
    const authDataB64 = base64urlEncode(authData);

    // 4. Sign: SHA-256(authData || SHA-256(clientDataJSON))
    const clientDataHash = sha256(clientDataBytes);
    const signedData = concat([authData, clientDataHash]);
    const signedDataB64 = base64urlEncode(signedData);
    const sigResult = await NativeKeys.sign(keyAlias, signedDataB64);

    // 5. Complete authentication
    const completeResp = await fido2Fetch<AuthenticateCompleteResponse>(
        origin,
        '/fido2/authenticate/complete',
        {
            type: 'authenticate_complete',
            challenge: options.challenge,
            credential_id: credentialId,
            client_data_json: clientDataB64,
            authenticator_data: authDataB64,
            signature: sigResult.signature,
            browser_session_id: browserSessionId,
        }
    );

    return { sessionToken: completeResp.session_token || '' };
}

// ── Internal helpers ────────────────────────────────────────────────────

function concat(arrays: Uint8Array[]): Uint8Array {
    let totalLen = 0;
    for (const a of arrays) totalLen += a.length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of arrays) {
        result.set(a, offset);
        offset += a.length;
    }
    return result;
}

/** Build a COSE_Key for P-256 (ES256). */
function buildCoseKey(x: Uint8Array, y: Uint8Array): Uint8Array {
    // CBOR map with 5 entries:
    // 1 (kty) => 2 (EC2)
    // 3 (alg) => -7 (ES256)
    // -1 (crv) => 1 (P-256)
    // -2 (x) => bstr
    // -3 (y) => bstr
    const parts: number[] = [];

    // Map(5)
    parts.push(0xa5);

    // 1 => 2
    parts.push(0x01, 0x02);
    // 3 => -7 (encoded as 0x26)
    parts.push(0x03, 0x26);
    // -1 => 1 (encoded as 0x20 for -1)
    parts.push(0x20, 0x01);
    // -2 => bstr(32)
    parts.push(0x21, 0x58, 0x20);
    const xArr = Array.from(x);
    parts.push(...xArr);
    // -3 => bstr(32)
    parts.push(0x22, 0x58, 0x20);
    const yArr = Array.from(y);
    parts.push(...yArr);

    return new Uint8Array(parts);
}
