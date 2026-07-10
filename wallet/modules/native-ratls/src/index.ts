// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { Platform } from 'react-native';
import { requireNativeModule } from 'expo-modules-core';
import type { AttestationResult, AttestationError, VerificationPolicy, PostResult, VerifyErrorKind } from './NativeRaTls.types.js';

const NativeRaTls = Platform.OS !== 'web' ? requireNativeModule('NativeRaTls') : null;

/** An Error carrying the native RA-TLS failure category, so callers can branch
 *  their recovery UX (continue-anyway vs show-the-problem). */
export class RaTlsError extends Error {
    kind?: VerifyErrorKind;
    constructor(result: AttestationError) {
        super(result.error);
        this.name = 'RaTlsError';
        this.kind = result.kind;
    }
}

/**
 * Connect to an enclave and inspect its RA-TLS attestation certificate.
 *
 * This does NOT verify the attestation — it only reads the certificate
 * extensions and returns them for display purposes.
 *
 * @param host  Enclave hostname or IP address.
 * @param port  Enclave port number.
 * @param caCertPath  Optional path to a CA PEM file on disk.
 * @returns Parsed attestation data from the certificate.
 */
export async function inspect(
    host: string,
    port: number,
    caCertPath?: string
): Promise<AttestationResult> {
    if (!NativeRaTls) throw new Error('NativeRaTls is not available on web');
    console.log(`[RA-TLS] inspect → ${host}:${port}`);
    let json: string;
    try {
        json = await NativeRaTls.inspect(host, port, caCertPath ?? null);
    } catch (e: any) {
        console.error(`[RA-TLS] inspect NATIVE THREW: ${e.message}`, e);
        throw e;
    }
    console.log(`[RA-TLS] inspect raw response (${json.length} chars): ${json.substring(0, 300)}`);
    const result: AttestationResult | AttestationError = JSON.parse(json);
    if ('error' in result) {
        console.error(`[RA-TLS] inspect error from native: ${result.error}`);
        throw new RaTlsError(result);
    }
    // Log whichever measurement is appropriate for the TEE family. TDX
    // exposes MRTD; SGX exposes MRENCLAVE. inspect() does parse the
    // attestation OIDs out of the cert (mrtd, mrenclave, workload_*,
    // platform fields), but does NOT verify the quote signature \u2014 that
    // requires a verify() call to the attestation server.
    const measurement =
        result.mrtd ?? result.mrenclave ?? null;
    console.log(
        `[RA-TLS] inspect OK — tee=${result.tee_type ?? 'unknown'} ` +
        `measurement=${measurement ? measurement.substring(0, 16) + '…' : 'none'}`
    );
    return result;
}

/**
 * Connect to an enclave and verify its RA-TLS certificate against a policy.
 *
 * In challenge mode, a nonce is sent in the TLS ClientHello so the enclave
 * binds it into a fresh attestation certificate, proving liveness.
 *
 * @param host    Enclave hostname or IP address.
 * @param port    Enclave port number.
 * @param policy  Verification policy specifying expected measurements.
 * @param caCertPath  Optional path to a CA PEM file on disk.
 * @returns Verified attestation data.
 * @throws If the certificate fails policy verification.
 */
export async function verify(
    host: string,
    port: number,
    policy: VerificationPolicy,
    caCertPath?: string
): Promise<AttestationResult> {
    if (!NativeRaTls) throw new Error('NativeRaTls is not available on web');
    const policyJson = JSON.stringify(policy);
    const json: string = await NativeRaTls.verify(host, port, caCertPath ?? null, policyJson);
    const result: AttestationResult | AttestationError = JSON.parse(json);
    if ('error' in result) throw new RaTlsError(result);
    return result;
}

/**
 * Connect to an enclave via RA-TLS and make an HTTP POST request.
 *
 * The connection uses the same RA-TLS handshake as inspect/verify,
 * so it accepts the enclave's self-signed attestation certificate.
 *
 * @param host  Enclave hostname or IP address.
 * @param port  Enclave port number.
 * @param path  HTTP path (e.g. "/fido2/register/begin").
 * @param body  JSON request body string.
 * @param headers  Optional extra request headers (e.g. the disclosure voucher).
 * @param caCertPath  Optional path to a CA PEM file on disk.
 * @returns Parsed response with status code and body.
 */
export async function post(
    host: string,
    port: number,
    path: string,
    body: string,
    headers?: Record<string, string>,
    caCertPath?: string
): Promise<PostResult> {
    if (!NativeRaTls) throw new Error('NativeRaTls is not available on web');
    console.log(`[RA-TLS] post → ${host}:${port}${path} (${body.length} bytes)`);
    const headersJson =
        headers && Object.keys(headers).length > 0 ? JSON.stringify(headers) : null;
    let json: string;
    try {
        json = await NativeRaTls.post(host, port, path, body, headersJson, caCertPath ?? null);
    } catch (e: any) {
        console.error(`[RA-TLS] post NATIVE THREW: ${e.message}`, e);
        throw e;
    }
    console.log(`[RA-TLS] post raw response (${json.length} chars): ${json.substring(0, 500)}`);
    const result: PostResult | AttestationError = JSON.parse(json);
    if ('error' in result) {
        console.error(`[RA-TLS] post error from native: ${result.error}${result.kind ? ` (${result.kind})` : ''}`);
        throw new RaTlsError(result);
    }
    console.log(`[RA-TLS] post OK — status=${result.status}, body=${result.body.substring(0, 200)}`);
    return result;
}

/**
 * Connect to an enclave via RA-TLS and make an HTTP request with an
 * arbitrary method (GET, POST, PUT, DELETE, ...).
 *
 * Same RA-TLS handshake as post(); an empty body sends no body (correct
 * for GET/DELETE).
 *
 * @param method  HTTP method (e.g. "GET").
 * @param host    Enclave hostname or IP address.
 * @param port    Enclave port number.
 * @param path    HTTP path (e.g. "/tools/list_root").
 * @param body    Request body string ("" for none).
 * @param headers Optional extra request headers.
 * @param caCertPath  Optional path to a CA PEM file on disk.
 * @returns Parsed response with status code and body.
 */
export async function request(
    method: string,
    host: string,
    port: number,
    path: string,
    body: string,
    headers?: Record<string, string>,
    caCertPath?: string
): Promise<PostResult> {
    if (!NativeRaTls) throw new Error('NativeRaTls is not available on web');
    const headersJson =
        headers && Object.keys(headers).length > 0 ? JSON.stringify(headers) : null;
    const json: string = await NativeRaTls.request(
        method, host, port, path, body, headersJson, caCertPath ?? null
    );
    const result: PostResult | AttestationError = JSON.parse(json);
    if ('error' in result) throw new RaTlsError(result);
    return result;
}

/**
 * A `fetch`-shaped adapter over the RA-TLS transport, suitable for
 * passing to an SDK that accepts a custom `fetch` (e.g.
 * `@privasys/drive-sdk`'s `PrivasysDrive.connect({ fetch })`).
 *
 * It routes requests whose host matches `enclaveHost` over RA-TLS (via
 * `request()`), and everything else over the platform `fetch` (so a
 * single injected fetch can serve both the enclave `baseUrl` and a
 * plain-TLS control-plane host like the management service).
 *
 * Only string/undefined bodies are supported over the RA-TLS leg
 * (JSON APIs); binary/streaming bodies fall back to an error, matching
 * the JSON-only transport. Response bodies are returned as text.
 */
export function makeRaTlsFetch(opts: {
    enclaveHost: string;
    port?: number;
    caCertPath?: string;
    platformFetch?: typeof fetch;
}): typeof fetch {
    const platformFetch = opts.platformFetch ?? fetch;
    const port = opts.port ?? 443;
    const adapter = async (input: any, init?: any): Promise<Response> => {
        const url = new URL(typeof input === 'string' ? input : input.url);
        if (url.hostname !== opts.enclaveHost) {
            return platformFetch(input as any, init);
        }
        const method = (init?.method ?? 'GET').toUpperCase();
        let body = '';
        if (init?.body != null) {
            if (typeof init.body !== 'string') {
                throw new Error('RA-TLS fetch adapter supports string bodies only');
            }
            body = init.body;
        }
        const headers: Record<string, string> = {};
        if (init?.headers) {
            const h = init.headers as any;
            if (typeof h.forEach === 'function') {
                h.forEach((v: string, k: string) => { headers[k] = v; });
            } else {
                for (const k of Object.keys(h)) headers[k] = h[k];
            }
        }
        const res = await request(
            method, opts.enclaveHost, port,
            url.pathname + url.search, body, headers, opts.caCertPath
        );
        return new Response(res.body, {
            status: res.status,
            headers: { 'Content-Type': 'application/json' },
        });
    };
    return adapter as unknown as typeof fetch;
}

export type { AttestationResult, AttestationError, VerificationPolicy, PostResult, VerifyErrorKind } from './NativeRaTls.types.js';
