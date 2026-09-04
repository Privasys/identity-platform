// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * RA-TLS attestation verification service.
 *
 * Wraps the native RA-TLS module to provide a high-level API for verifying
 * enclave attestation during the connect / KYC / drive flows.
 *
 * `attestEnclave` is the entry point every flow should use: it picks the
 * verification mode (deterministic vs challenge, the latter binding the
 * evidence to the connection), always consults the attestation service, and turns the
 * native layer's typed failures into a structured {@link AttestationOutcome}
 * so callers can render the right recovery UX (continue-anyway vs
 * show-the-problem-with-an-override).
 */

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

/**
 * Every Privasys enclave is published under one of these, and nothing else is.
 *
 * RA-TLS v2 makes the caller state up front whether it expects an attested peer,
 * so the wallet has to decide before it opens the connection rather than
 * inspecting a certificate and finding out. The hostname IS the rule.
 *
 * The test fleet is a separate suffix rather than a wildcard over
 * `privasys.org`, because the difference between "an enclave" and "a Privasys
 * web property" is exactly what this decides. `privasys.id` and
 * `api.developer.privasys.org` are ours too and neither is an enclave.
 *
 * A host under the test suffix does NOT also match the production one:
 * `x.apps.test.privasys.org` does not end in `.apps.privasys.org`, so both have
 * to be listed.
 */
const ENCLAVE_HOST_SUFFIXES = ['.apps.privasys.org', '.apps.test.privasys.org'];

/**
 * Can this host be expected to present enclave evidence?
 *
 * Both answers fail safe. A real enclave published somewhere else is treated as
 * an ordinary host: less trust claimed than is available, never more. A
 * non-enclave under the enclave suffix is asked for evidence it cannot give and
 * the connection fails loudly. Neither direction lets an unattested peer be
 * shown to the holder as attested, which is the only outcome that would matter.
 *
 * Suffix match, so `apps.privasys.org` itself is not an enclave and neither is
 * `something.apps.privasys.org.example.com`. Lower-cased, trailing root dot
 * removed, and any port dropped, because all three arrive from QR payloads that
 * the wallet does not control.
 */
export function isAttestableHost(host: string): boolean {
    const bare = String(host ?? '')
        .trim()
        .toLowerCase()
        .split(':')[0]
        .replace(/\.$/, '');
    return ENCLAVE_HOST_SUFFIXES.some(
        (suffix) => bare.length > suffix.length && bare.endsWith(suffix),
    );
}

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
    /** True when the evidence was bound to this connection (challenge mode). */
    challenged: boolean;
    /** Present when `status === 'verified'`. */
    result?: AttestationResult;
    /** Native failure category, when not verified. */
    kind?: VerifyErrorKind;
    /**
     * True when the attestation service was never CALLED, because this device
     * could not produce an App Attest / Play Integrity token to authenticate
     * with. Distinct from the service being down: it says nothing at all about
     * the app being connected to, and the approval screen must not imply that
     * the app failed a check that never ran.
     */
    deviceUnattested?: boolean;
    /** Human-readable problem, when not verified. */
    message?: string;
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
 * TLS channel binder into a fresh quote. The attestation service is consulted
 * whenever we hold its bearer; without one we report it unavailable (below).
 */
export async function attestEnclave(
    origin: string,
    opts: AttestOptions
): Promise<AttestationOutcome> {
    const challenged = opts.mode === 'challenge';
    // No bearer → we cannot get the attestation service's verdict. Report it as
    // unavailable so the connect flow shows the "continue anyway" recovery UX
    // (identical to a network-unreachable service), rather than sending an empty
    // bearer the service would simply reject. In production the token is present;
    // getAttestationServerToken degrades to '' only when the device genuinely
    // cannot attest (e.g. a debug build on an emulator).
    if (!opts.attestationServerToken) {
        return {
            status: 'unreachable',
            mode: opts.mode,
            challenged,
            deviceUnattested: true,
            // Diagnostic only. The screen renders its own sentence for this
            // case rather than interpolating a technical phrase that blamed
            // the wrong party (2026-08-26).
            message: 'no App Attest or Play Integrity token available',
        };
    }
    const { host, port } = splitOrigin(origin);
    const policy: VerificationPolicy = {
        tee: opts.tee,
        // Challenge mode binds the evidence to this connection (the native layer
        // draws the fresh context); deterministic accepts the cached quote.
        attestation: opts.mode,
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
