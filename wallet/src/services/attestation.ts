// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * RA-TLS attestation verification service.
 *
 * Wraps the native RA-TLS module to provide a high-level API for verifying
 * enclave attestation during the connect / KYC / drive flows.
 *
 * `attestEnclave` is the entry point every flow should use: it picks the
 * verification mode (deterministic vs challenge), generates a fresh nonce for
 * challenge mode, always consults the attestation service, and turns the
 * native layer's typed failures into a structured {@link AttestationOutcome}
 * so callers can render the right recovery UX (continue-anyway vs
 * show-the-problem-with-an-override).
 */

import * as Crypto from 'expo-crypto';
import { bytesToHex } from '@noble/hashes/utils.js';

import * as NativeRaTls from '../../modules/native-ratls/src/index';
import { RaTlsError } from '../../modules/native-ratls/src/index';
import type {
    AttestationResult,
    VerificationPolicy,
    VerifyErrorKind,
} from '../../modules/native-ratls/src/NativeRaTls.types';
import type { VerificationMode } from '@/stores/settings';

export type { AttestationResult, VerificationPolicy };
export type { VerificationMode };

/** Canonical attestation service endpoint. */
export const AS_ENDPOINT = 'https://as.privasys.org';

type Tee = NonNullable<VerificationPolicy['tee']>;

/** Terminal state of an attestation attempt. */
export type AttestationStatus =
    /** Verified — `result` is present and trustworthy. */
    | 'verified'
    /** No verdict (attestation service unreachable). Offer "continue anyway". */
    | 'unreachable'
    /** A definite negative verdict (bad quote, or the service rejected it).
     *  Show the problem; allow an explicit, deliberate override. */
    | 'invalid'
    /** Could not reach/handshake the enclave, or an unexpected failure. Retry;
     *  there is nothing to override. */
    | 'error';

export interface AttestationOutcome {
    status: AttestationStatus;
    /** The verification mode actually used. */
    mode: VerificationMode;
    /** True when a fresh nonce + channel binder were folded in (challenge mode). */
    challenged: boolean;
    /** Present when `status === 'verified'`. */
    result?: AttestationResult;
    /** Native failure category, when not verified. */
    kind?: VerifyErrorKind;
    /** Human-readable problem, when not verified. */
    message?: string;
}

/** Fresh 32-byte random nonce, hex-encoded — regenerated for every challenge. */
function freshNonceHex(): string {
    return bytesToHex(Crypto.getRandomBytes(32));
}

function splitOrigin(origin: string): { host: string; port: number } {
    const url = new URL(`https://${origin}`);
    return { host: url.hostname, port: parseInt(url.port || '443', 10) };
}

function statusForKind(kind: VerifyErrorKind | undefined): AttestationStatus {
    switch (kind) {
        case 'as_unreachable':
            return 'unreachable';
        case 'quote_invalid':
        case 'as_rejected':
            return 'invalid';
        case 'connection':
        case 'config':
        default:
            return 'error';
    }
}

export interface AttestOptions {
    tee: Tee;
    /** Verification mode. Callers pass the settings default, or force
     *  `'challenge'` when the user taps "Challenge this enclave". */
    mode: VerificationMode;
    /** Bearer token for the attestation service (per-session, short-lived). */
    attestationServerToken?: string;
    /** Override the attestation service endpoint. Defaults to {@link AS_ENDPOINT}. */
    attestationServer?: string;
}

/**
 * Verify an enclave and return a structured outcome (never throws for a
 * verification verdict — only genuinely unexpected errors surface as
 * `status: 'error'`).
 *
 * Deterministic mode binds report_data to the certificate's NotBefore;
 * challenge mode sends a fresh random nonce so the enclave folds it plus the
 * TLS channel binder into a fresh quote. The attestation service is always
 * consulted.
 */
export async function attestEnclave(
    origin: string,
    opts: AttestOptions
): Promise<AttestationOutcome> {
    const { host, port } = splitOrigin(origin);
    const challenged = opts.mode === 'challenge';
    const policy: VerificationPolicy = {
        tee: opts.tee,
        report_data_mode: opts.mode,
        // A fresh nonce every time — never reuse a session id or QR nonce.
        nonce: challenged ? freshNonceHex() : undefined,
        attestation_server: opts.attestationServer ?? AS_ENDPOINT,
        attestation_server_token: opts.attestationServerToken,
    };

    try {
        const result = await NativeRaTls.verify(host, port, policy);
        return { status: 'verified', mode: opts.mode, challenged, result };
    } catch (e: any) {
        const kind: VerifyErrorKind | undefined =
            e instanceof RaTlsError ? e.kind : undefined;
        const status = e instanceof RaTlsError ? statusForKind(kind) : 'error';
        console.warn(
            `[attest] ${origin} ${opts.mode} → ${status}` +
            `${kind ? ` (${kind})` : ''}: ${e?.message}`
        );
        return {
            status,
            mode: opts.mode,
            challenged,
            kind,
            message: e?.message ?? 'attestation failed',
        };
    }
}

/**
 * Low-level verify against an explicit policy. Throws {@link RaTlsError} on
 * failure (carrying `.kind`). Prefer {@link attestEnclave} in flows.
 */
export async function verifyAttestation(
    origin: string,
    policy: VerificationPolicy
): Promise<AttestationResult> {
    const { host, port } = splitOrigin(origin);
    return NativeRaTls.verify(host, port, policy);
}

/**
 * Inspect an enclave's certificate without policy verification.
 * Used for displaying attestation details before the user decides to trust.
 */
export async function inspectAttestation(origin: string): Promise<AttestationResult> {
    const { host, port } = splitOrigin(origin);
    return NativeRaTls.inspect(host, port);
}
