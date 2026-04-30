// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * FIDO2 client-side operations.
 *
 * Handles the WebAuthn registration and authentication ceremonies by
 * communicating with the FIDO2 server over an RA-TLS connection.
 */

import { sha256 } from '@noble/hashes/sha2.js';

import * as NativeKeys from '../../modules/native-keys/src/index';
import * as NativeRaTls from '../../modules/native-ratls/src/index';

// ── Wire types matching the WebAuthn specification ──────────────────────
// Server returns standard PublicKeyCredentialCreationOptions / RequestOptions.
// Wallet sends standard AuthenticatorAttestationResponse / AssertionResponse.

interface CredentialCreationOptions {
    publicKey: {
        rp: { id: string; name: string };
        user: { id: string; name: string; displayName: string };
        challenge: string; // base64url
        pubKeyCredParams: Array<{ type: string; alg: number }>;
        timeout?: number;
        authenticatorSelection?: {
            authenticatorAttachment?: string;
            userVerification?: string;
        };
        attestation?: string;
    };
}

interface CredentialAssertionOptions {
    publicKey: {
        challenge: string; // base64url
        timeout?: number;
        rpId?: string;
        allowCredentials?: Array<{ type: string; id: string }>;
        userVerification?: string;
    };
}

interface CompleteResponse {
    status: string;
    sessionToken?: string;
    userId?: string;
    /** BIP39 24-word recovery phrase. Returned ONCE on first registration. */
    recoveryPhrase?: string;
}

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

    const json: T = JSON.parse(result.body);
    if ('error' in json && typeof (json as any).error === 'string') {
        const msg = (json as any).error;
        console.error(`[FIDO2] ${path} — server error: ${msg}`);
        throw new Error(`FIDO2 error: ${msg}`);
    }
    return json;
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
 * Register a new FIDO2 credential with a server.
 *
 * @param origin  The server origin (hostname or hostname:port).
 * @param keyAlias  The hardware key alias to use (from native-keys).
 * @param browserSessionId  Session ID to relay the session token to the browser.
 * @returns The session token for the browser and the credential ID.
 */
export async function register(
    origin: string,
    keyAlias: string,
    browserSessionId: string,
    displayName?: string,
    userHandleOverride?: string
): Promise<{ sessionToken: string; credentialId: string; userHandle: string; userName: string; serverRpId: string; userId?: string; recoveryPhrase?: string }> {
    // 1. Begin registration — get challenge and options from server.
    //    If the caller provides a userHandle (e.g. the canonical privasys.id
    //    user_id derived from the pairwise seed) use it so all of the user's
    //    devices map to the same server-side `user_id`. Otherwise generate a
    //    fresh random 32-byte handle.
    let userHandle: string;
    if (userHandleOverride) {
        userHandle = userHandleOverride;
    } else {
        const userHandleBytes = new Uint8Array(32);
        crypto.getRandomValues(userHandleBytes);
        userHandle = base64urlEncode(userHandleBytes);
    }

    const beginResp = await fido2Fetch<CredentialCreationOptions>(
        origin,
        `/fido2/register/begin?session_id=${encodeURIComponent(browserSessionId)}`,
        {
            userName: displayName || keyAlias,
            userHandle,
        }
    );
    const options = beginResp.publicKey;

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

    // 7. Complete registration — send standard WebAuthn credential response
    const credentialIdB64 = base64urlEncode(credentialIdBytes);
    const completeResp = await fido2Fetch<CompleteResponse>(
        origin,
        `/fido2/register/complete?challenge=${encodeURIComponent(options.challenge)}`,
        {
            id: credentialIdB64,
            rawId: credentialIdB64,
            type: 'public-key',
            response: {
                clientDataJSON: clientDataB64,
                attestationObject: base64urlEncode(attestationObject),
            },
        }
    );

    return {
        sessionToken: completeResp.sessionToken || '',
        credentialId: credentialIdB64,
        userHandle: options.user.id,
        userName: options.user.name,
        serverRpId: options.rp.id,
        userId: completeResp.userId,
        recoveryPhrase: completeResp.recoveryPhrase,
    };
}

/**
 * Authenticate with an existing FIDO2 credential.
 *
 * @param origin  The server origin (hostname or hostname:port).
 * @param keyAlias  The hardware key alias.
 * @param credentialId  The credential ID to authenticate with.
 * @param browserSessionId  Session ID to relay the session token to the browser.
 * @param rpId  The RP ID to use for rpIdHash (from registration). Falls back to origin hostname.
 * @returns The session token for the browser.
 */
export async function authenticate(
    origin: string,
    keyAlias: string,
    credentialId: string,
    browserSessionId: string,
    rpId?: string,
    sessionRelay?: { sdkPub: string; appHost: string; quoteHash: string; nonce: string }
): Promise<{ sessionToken: string; userId?: string; sessionRelay?: SessionRelayBinding }> {
    // 0. Optional: bootstrap a browser→enclave session over the same
    //    RA-TLS connection. Wallet posts the SDK's ephemeral P-256
    //    public key (SEC1 uncompressed, base64url) and gets back the
    //    server's pub + session id. We then derive a binding challenge
    //    over (nonce, sdk_pub, quote_hash, enc_pub, session_id) — the
    //    IdP recomputes and rejects on mismatch, so the issued JWT is
    //    cryptographic proof that the wallet attested those values.
    //
    //    The bootstrap call MUST go to the enclave app (`appHost`), NOT
    //    the IdP `origin`: only the enclave runs the sealed-CBOR
    //    middleware. The IdP `origin` is the privasys.id host that
    //    serves the FIDO2 ceremony.
    let relay: SessionRelayBinding | undefined;
    let bindingChallengeB64: string | undefined;
    if (sessionRelay?.sdkPub) {
        if (!sessionRelay.appHost) {
            throw new Error('session-relay flow requires appHost');
        }
        const bs = await fido2Fetch<{ session_id: string; enc_pub: string; expires_at: number }>(
            sessionRelay.appHost,
            '/__privasys/session-bootstrap',
            { sdk_pub: sessionRelay.sdkPub },
        );
        relay = {
            sessionId: bs.session_id,
            encPub: bs.enc_pub,
            sdkPub: sessionRelay.sdkPub,
            expiresAt: bs.expires_at,
        };
        const binding = computeSessionRelayBinding(
            sessionRelay.nonce,
            sessionRelay.sdkPub,
            sessionRelay.quoteHash,
            relay.encPub,
            relay.sessionId,
        );
        bindingChallengeB64 = base64urlEncode(binding);
    }

    // 1. Begin authentication. When in the session-relay flow we hand the
    //    pre-computed binding to the IdP so it returns it as the
    //    WebAuthn challenge to sign.
    let beginPath = `/fido2/authenticate/begin?session_id=${encodeURIComponent(browserSessionId)}`;
    if (bindingChallengeB64) {
        beginPath += `&binding_challenge=${encodeURIComponent(bindingChallengeB64)}`;
    }
    const beginResp = await fido2Fetch<CredentialAssertionOptions>(
        origin,
        beginPath,
        {
            credentialId,
        }
    );
    const options = beginResp.publicKey;
    if (bindingChallengeB64 && options.challenge !== bindingChallengeB64) {
        throw new Error('FIDO2 server returned a challenge that does not match the requested binding');
    }

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
    const effectiveRpId = rpId || origin.split(':')[0];
    const rpIdHash = sha256(new TextEncoder().encode(effectiveRpId));
    const flags = new Uint8Array([0x05]); // UP | UV
    const signCount = new Uint8Array([0, 0, 0, 0]); // platform authenticator: always 0

    const authData = concat([rpIdHash, flags, signCount]);
    const authDataB64 = base64urlEncode(authData);

    // 4. Sign: authData || SHA-256(clientDataJSON) per WebAuthn spec
    const clientDataHash = sha256(clientDataBytes);
    const signedData = concat([authData, clientDataHash]);
    const signedDataB64 = base64urlEncode(signedData);
    const sigResult = await NativeKeys.sign(keyAlias, signedDataB64);

    // 5. Complete authentication — send standard WebAuthn assertion response
    let completePath = `/fido2/authenticate/complete?challenge=${encodeURIComponent(options.challenge)}`;
    if (relay && sessionRelay) {
        completePath +=
            `&session_id=${encodeURIComponent(relay.sessionId)}` +
            `&enc_pub=${encodeURIComponent(relay.encPub)}` +
            `&sdk_pub=${encodeURIComponent(relay.sdkPub)}` +
            `&nonce=${encodeURIComponent(sessionRelay.nonce)}` +
            `&quote_hash=${encodeURIComponent(sessionRelay.quoteHash)}`;
    }
    const completeResp = await fido2Fetch<CompleteResponse>(
        origin,
        completePath,
        {
            id: credentialId,
            rawId: credentialId,
            type: 'public-key',
            response: {
                clientDataJSON: clientDataB64,
                authenticatorData: authDataB64,
                signature: sigResult.signature,
            },
        }
    );

    return { sessionToken: completeResp.sessionToken || '', userId: completeResp.userId, sessionRelay: relay };
}

/** Result of a session-relay bootstrap, returned from authenticate() when
 *  the caller requested `mode:"session-relay"`. */
export interface SessionRelayBinding {
    sessionId: string;
    /** Server P-256 SEC1 uncompressed pubkey, base64url. */
    encPub: string;
    /** Echo of the SDK pubkey supplied by the caller, base64url. */
    sdkPub: string;
    expiresAt: number;
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

/**
 * Compute the session-relay WebAuthn challenge binding per §3.3 of the
 * design. Mirrors the IdP's `computeSessionRelayBinding` in
 * `internal/fido2/handler.go`.
 *
 * Inputs are accepted as the same encodings the IdP query params carry:
 * - nonce, sdkPub, encPub: base64url (no padding required)
 * - quoteHash, sessionIdHex: hex
 */
function computeSessionRelayBinding(
    nonceB64: string,
    sdkPubB64: string,
    quoteHashHex: string,
    encPubB64: string,
    sessionIdHex: string,
): Uint8Array {
    const nonce = base64urlDecode(nonceB64);
    const sdkPub = base64urlDecode(sdkPubB64);
    const quoteHash = hexDecode(quoteHashHex);
    const encPub = base64urlDecode(encPubB64);
    const sessionId = hexDecode(sessionIdHex);
    const domain = new TextEncoder().encode('privasys-session-relay/v1');
    return sha256(concat([domain, nonce, sdkPub, quoteHash, encPub, sessionId]));
}

function hexDecode(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) throw new Error('hex string has odd length');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
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
