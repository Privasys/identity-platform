// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Node.js software FIDO2/WebAuthn client used by e2e tests to authenticate
 * against the Privasys IdP without a real wallet.
 *
 * Mirrors `auth/wallet/src/services/fido2.ts` but uses Node `crypto`
 * (P-256 ECDSA, raw DER signatures — exactly what go-webauthn expects).
 *
 * Persists the test identity (P-256 keypair + credentialId + userHandle)
 * to a file under `.auth/fido2-<RP>.json` so subsequent runs reuse the
 * same `user_id` server-side. Delete that file to "lose your phone" and
 * re-register from scratch.
 */
import {
    createPrivateKey,
    createPublicKey,
    createSign,
    generateKeyPairSync,
    createHash,
    type KeyObject
} from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

// ── Helpers ──────────────────────────────────────────────────────────────

const b64url = (b: Buffer | Uint8Array): string =>
    Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const fromB64url = (s: string): Buffer => {
    const pad = (4 - (s.length % 4)) % 4;
    return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad), 'base64');
};

const sha256 = (data: Buffer | Uint8Array): Buffer => createHash('sha256').update(data).digest();

const concat = (parts: (Buffer | Uint8Array)[]): Buffer =>
    Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p))));

// AAGUID identifying the e2e test client (distinct from the wallet's).
const E2E_TEST_AAGUID = Buffer.from('e2e7e57c0000000000000000000000c1', 'hex'); // 16 bytes

// ── CBOR encoding (only what we need) ────────────────────────────────────

function cborTextStr(s: string): Buffer {
    const bytes = Buffer.from(s, 'utf-8');
    const len = bytes.length;
    if (len < 24) return concat([Buffer.from([0x60 | len]), bytes]);
    if (len < 256) return concat([Buffer.from([0x78, len]), bytes]);
    throw new Error('cbor text too long');
}

function cborBytes(b: Buffer): Buffer {
    const len = b.length;
    if (len < 24) return concat([Buffer.from([0x40 | len]), b]);
    if (len < 256) return concat([Buffer.from([0x58, len]), b]);
    if (len < 65536) return concat([Buffer.from([0x59, (len >> 8) & 0xff, len & 0xff]), b]);
    throw new Error('cbor bytes too long');
}

function cborMapHeader(n: number): Buffer {
    if (n < 24) return Buffer.from([0xa0 | n]);
    throw new Error('cbor map too large');
}

/** Build a COSE_Key for P-256 (ES256). */
function buildCoseKey(x: Buffer, y: Buffer): Buffer {
    const parts: Buffer[] = [];
    parts.push(cborMapHeader(5));
    // 1 (kty) => 2 (EC2)
    parts.push(Buffer.from([0x01, 0x02]));
    // 3 (alg) => -7 (ES256)
    parts.push(Buffer.from([0x03, 0x26]));
    // -1 (crv) => 1 (P-256)
    parts.push(Buffer.from([0x20, 0x01]));
    // -2 (x) => bstr(32)
    parts.push(Buffer.from([0x21]));
    parts.push(cborBytes(x));
    // -3 (y) => bstr(32)
    parts.push(Buffer.from([0x22]));
    parts.push(cborBytes(y));
    return concat(parts);
}

/** Build attestationObject with fmt="none". */
function buildAttestationObject(authData: Buffer): Buffer {
    return concat([
        cborMapHeader(3),
        cborTextStr('fmt'),
        cborTextStr('none'),
        cborTextStr('attStmt'),
        cborMapHeader(0),
        cborTextStr('authData'),
        cborBytes(authData)
    ]);
}

// ── Keypair persistence ─────────────────────────────────────────────────

interface PersistedIdentity {
    /** PEM-encoded PKCS#8 private key. */
    privateKeyPem: string;
    /** Raw 32-byte X coordinate, base64url. */
    x: string;
    /** Raw 32-byte Y coordinate, base64url. */
    y: string;
    /** Random 32-byte user_id used as WebAuthn userHandle, base64url. */
    userHandle: string;
    /** Server-issued credential_id, base64url (set after first registration). */
    credentialId?: string;
    /** Server-side user_id (same as userHandle decoded). */
    userId?: string;
}

interface FidoIdentity {
    privateKey: KeyObject;
    publicKey: KeyObject;
    x: Buffer;
    y: Buffer;
    /** base64url-encoded raw bytes used as WebAuthn userHandle. */
    userHandle: string;
    /** decoded userHandle bytes treated as the server user_id (string). */
    userId: string;
    credentialId?: string;
    persistedPath: string;
    persisted: PersistedIdentity;
}

function rawCoordsFromPubKey(pub: KeyObject): { x: Buffer; y: Buffer } {
    // SPKI DER → uncompressed point. Easiest: jwk export.
    const jwk = pub.export({ format: 'jwk' });
    if (!jwk.x || !jwk.y) throw new Error('not an EC public key');
    return { x: fromB64url(jwk.x), y: fromB64url(jwk.y) };
}

export function loadOrCreateIdentity(filePath: string): FidoIdentity {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });

    let persisted: PersistedIdentity;
    if (fs.existsSync(filePath)) {
        persisted = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as PersistedIdentity;
    } else {
        const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const { x, y } = rawCoordsFromPubKey(publicKey);
        // Random 32-byte user_id (will become server-side user_id).
        const uhBytes = Buffer.alloc(32);
        for (let i = 0; i < 32; i++) uhBytes[i] = Math.floor(Math.random() * 256);
        persisted = {
            privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }) as string,
            x: b64url(x),
            y: b64url(y),
            userHandle: b64url(uhBytes)
        };
        fs.writeFileSync(filePath, JSON.stringify(persisted, null, 2));
        console.log(`[e2e-fido2] generated new identity at ${filePath}`);
    }

    const privateKey = createPrivateKey(persisted.privateKeyPem);
    const publicKey = createPublicKey(privateKey);
    const x = fromB64url(persisted.x);
    const y = fromB64url(persisted.y);
    // The IdP keys `users.user_id` on whatever string we pass as userHandle
    // (handler.go: `userID := req.UserHandle`). So our server-side user_id
    // IS the base64url userHandle string itself.
    const userId = persisted.userHandle;

    return {
        privateKey,
        publicKey,
        x,
        y,
        userHandle: persisted.userHandle,
        userId,
        credentialId: persisted.credentialId,
        persistedPath: filePath,
        persisted
    };
}

function persist(identity: FidoIdentity): void {
    fs.writeFileSync(identity.persistedPath, JSON.stringify(identity.persisted, null, 2));
}

// ── HTTP helper ──────────────────────────────────────────────────────────

async function postJson<T>(url: string, body: unknown, headers: Record<string, string> = {}): Promise<T> {
    const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body)
    });
    const text = await resp.text();
    if (!resp.ok) {
        const err = new Error(`POST ${url} → ${resp.status}: ${text}`) as Error & { status?: number };
        err.status = resp.status;
        throw err;
    }
    return JSON.parse(text) as T;
}

// ── WebAuthn ceremonies ─────────────────────────────────────────────────

interface BeginRegOptions {
    publicKey: {
        rp: { id: string; name: string };
        user: { id: string; name: string; displayName: string };
        challenge: string;
        pubKeyCredParams: { type: string; alg: number }[];
    };
}

interface BeginAuthOptions {
    publicKey: {
        challenge: string;
        rpId: string;
        allowCredentials?: { id: string; type: string }[];
    };
}

interface CompleteResp {
    status?: string;
    sessionToken?: string;
    userId?: string;
    recoveryPhrase?: string;
}

export interface RegisterResult {
    sessionToken: string;
    userId: string;
    credentialId: string;
    recoveryPhrase?: string;
}

export interface AuthenticateResult {
    sessionToken: string;
    userId: string;
}

/**
 * Register a new FIDO2 credential at the IdP for our persisted identity.
 * Pass `sessionId` to bind this registration to an in-flight OIDC session
 * (set by `/authorize`); empty string for standalone registration.
 */
export async function fido2Register(
    issuerOrigin: string,
    rpId: string,
    identity: FidoIdentity,
    sessionId: string,
    displayName: string
): Promise<RegisterResult> {
    const beginUrl = `${issuerOrigin}/fido2/register/begin?session_id=${encodeURIComponent(sessionId)}`;
    const begin = await postJson<BeginRegOptions>(beginUrl, {
        userName: displayName,
        userHandle: identity.userHandle
    });
    const challenge = begin.publicKey.challenge;

    // clientDataJSON
    const clientData = JSON.stringify({
        type: 'webauthn.create',
        challenge,
        origin: `https://${rpId}`,
        crossOrigin: false
    });
    const clientDataBytes = Buffer.from(clientData, 'utf-8');

    // attestedCredentialData: AAGUID || credIdLen(2) || credId || cosePubKey
    const credentialIdBytes = sha256(concat([identity.x, identity.y]));
    const credIdLen = Buffer.from([
        (credentialIdBytes.length >> 8) & 0xff,
        credentialIdBytes.length & 0xff
    ]);
    const coseKey = buildCoseKey(identity.x, identity.y);
    const attestedCredData = concat([E2E_TEST_AAGUID, credIdLen, credentialIdBytes, coseKey]);

    // authData = rpIdHash || flags(UP|UV|AT=0x45) || signCount(0) || attestedCredData
    const rpIdHash = sha256(Buffer.from(rpId, 'utf-8'));
    const flags = Buffer.from([0x45]);
    const signCount = Buffer.from([0, 0, 0, 0]);
    const authData = concat([rpIdHash, flags, signCount, attestedCredData]);

    const attestationObject = buildAttestationObject(authData);
    const credentialIdB64 = b64url(credentialIdBytes);

    const completeUrl = `${issuerOrigin}/fido2/register/complete?challenge=${encodeURIComponent(challenge)}`;
    const complete = await postJson<CompleteResp>(completeUrl, {
        id: credentialIdB64,
        rawId: credentialIdB64,
        type: 'public-key',
        response: {
            clientDataJSON: b64url(clientDataBytes),
            attestationObject: b64url(attestationObject)
        }
    });

    if (!complete.sessionToken) throw new Error('register/complete: no sessionToken');

    // Persist credentialId + userId
    identity.credentialId = credentialIdB64;
    identity.persisted.credentialId = credentialIdB64;
    identity.persisted.userId = complete.userId;
    persist(identity);

    return {
        sessionToken: complete.sessionToken,
        userId: complete.userId || identity.userId,
        credentialId: credentialIdB64,
        recoveryPhrase: complete.recoveryPhrase
    };
}

/** Authenticate with an existing credential. */
export async function fido2Authenticate(
    issuerOrigin: string,
    rpId: string,
    identity: FidoIdentity,
    sessionId: string
): Promise<AuthenticateResult> {
    if (!identity.credentialId) throw new Error('no credentialId — register first');

    const beginUrl = `${issuerOrigin}/fido2/authenticate/begin?session_id=${encodeURIComponent(sessionId)}`;
    const begin = await postJson<BeginAuthOptions>(beginUrl, { credentialId: identity.credentialId });
    const challenge = begin.publicKey.challenge;

    const clientData = JSON.stringify({
        type: 'webauthn.get',
        challenge,
        origin: `https://${rpId}`,
        crossOrigin: false
    });
    const clientDataBytes = Buffer.from(clientData, 'utf-8');

    const rpIdHash = sha256(Buffer.from(rpId, 'utf-8'));
    const flags = Buffer.from([0x05]); // UP | UV
    const signCount = Buffer.from([0, 0, 0, 0]);
    const authData = concat([rpIdHash, flags, signCount]);

    // Sign: SHA-256 over (authData || SHA-256(clientDataJSON))
    const clientDataHash = sha256(clientDataBytes);
    const signedData = concat([authData, clientDataHash]);
    const signer = createSign('SHA256');
    signer.update(signedData);
    signer.end();
    const signatureDer = signer.sign(identity.privateKey);

    const completeUrl = `${issuerOrigin}/fido2/authenticate/complete?challenge=${encodeURIComponent(challenge)}`;
    const complete = await postJson<CompleteResp>(completeUrl, {
        id: identity.credentialId,
        rawId: identity.credentialId,
        type: 'public-key',
        response: {
            clientDataJSON: b64url(clientDataBytes),
            authenticatorData: b64url(authData),
            signature: b64url(signatureDer)
        }
    });

    if (!complete.sessionToken) throw new Error('authenticate/complete: no sessionToken');
    return {
        sessionToken: complete.sessionToken,
        userId: complete.userId || identity.userId
    };
}
