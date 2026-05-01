// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { Platform } from 'react-native';
import { requireNativeModule } from 'expo-modules-core';
import type { AttestationResult, AttestationError, VerificationPolicy, PostResult } from './NativeRaTls.types.js';

const NativeRaTls = Platform.OS !== 'web' ? requireNativeModule('NativeRaTls') : null;

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
        throw new Error(result.error);
    }
    // Log whichever measurement is appropriate for the TEE family. TDX
    // exposes MRTD; SGX exposes MRENCLAVE. inspect() does not verify the
    // quote, so other quote-derived fields (code_hash, config_merkle_root,
    // quote_verification_status, …) are intentionally null here.
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
    if ('error' in result) throw new Error(result.error);
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
 * @param caCertPath  Optional path to a CA PEM file on disk.
 * @returns Parsed response with status code and body.
 */
export async function post(
    host: string,
    port: number,
    path: string,
    body: string,
    caCertPath?: string
): Promise<PostResult> {
    if (!NativeRaTls) throw new Error('NativeRaTls is not available on web');
    console.log(`[RA-TLS] post → ${host}:${port}${path} (${body.length} bytes)`);
    let json: string;
    try {
        json = await NativeRaTls.post(host, port, path, body, caCertPath ?? null);
    } catch (e: any) {
        console.error(`[RA-TLS] post NATIVE THREW: ${e.message}`, e);
        throw e;
    }
    console.log(`[RA-TLS] post raw response (${json.length} chars): ${json.substring(0, 500)}`);
    const result: PostResult | AttestationError = JSON.parse(json);
    if ('error' in result) {
        console.error(`[RA-TLS] post error from native: ${result.error}`);
        throw new Error(result.error);
    }
    console.log(`[RA-TLS] post OK — status=${result.status}, body=${result.body.substring(0, 200)}`);
    return result;
}

export type { AttestationResult, AttestationError, VerificationPolicy, PostResult } from './NativeRaTls.types.js';
