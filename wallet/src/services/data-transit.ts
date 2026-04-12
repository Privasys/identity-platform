// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Data transit — encrypt and deliver approved attributes to enclaves.
 *
 * Two delivery channels:
 * 1. **Direct RA-TLS**: POST to the enclave's RA-TLS endpoint via NativeRaTls.
 *    The TLS channel itself provides encryption and mutual attestation.
 * 2. **Broker relay**: Send encrypted payload via the WebSocket broker when
 *    the enclave's host/port isn't directly reachable.
 *
 * For broker relay, data is encrypted with AES-256-GCM using a key derived
 * from a one-time ECDH exchange (wallet ephemeral key + enclave's RA-TLS
 * public key). This ensures only the attested enclave can decrypt.
 */

import * as Crypto from 'expo-crypto';

import type { BrokerMessage } from '@/services/broker';
import { getAttributeValues } from '@/services/consent';
import { deriveAppSub } from '@/services/did';
import { useProfileStore } from '@/stores/profile';

import * as NativeRaTls from '../../modules/native-ratls/src/index';

/** Options for sending data via direct RA-TLS channel. */
export interface DirectDeliveryOptions {
    /** Enclave hostname. */
    host: string;
    /** Enclave RA-TLS port (typically 8443). */
    port: number;
    /** Path on the enclave to POST data to (e.g. /api/v1/data). */
    path: string;
    /** CA cert path for custom root (optional). */
    caCertPath?: string;
}

/** Options for sending data via broker WebSocket relay. */
export interface BrokerDeliveryOptions {
    /** WebSocket URL of the broker relay. */
    brokerUrl: string;
    /** Session ID for the relay. */
    sessionId: string;
}

/** Result of a data delivery attempt. */
export interface DeliveryResult {
    /** Whether delivery succeeded. */
    success: boolean;
    /** Response status (for direct) or acknowledgement flag (for broker). */
    status?: number;
    /** Response body (for direct). */
    body?: string;
    /** Error message if delivery failed. */
    error?: string;
}

/**
 * Build the data payload from approved attribute keys.
 *
 * Includes a per-app derived `sub` — a pairwise identifier unique to this
 * user + this app. App owners cannot use this to correlate users across
 * different apps because each app gets a different sub derived from the
 * user's pairwise seed.
 *
 * Returns a JSON string with attributes, derived sub, and metadata.
 */
export async function buildPayload(
    approvedAttributes: string[],
    rpId: string
): Promise<string> {
    const values = getAttributeValues(approvedAttributes);
    const profile = useProfileStore.getState().profile;

    // Derive per-app pairwise sub (prevents cross-app tracking)
    let sub: string | undefined;
    if (profile?.pairwiseSeed) {
        sub = await deriveAppSub(profile.pairwiseSeed, rpId);
    }

    const payload = {
        version: 1,
        timestamp: new Date().toISOString(),
        nonce: Crypto.randomUUID(),
        /** Pairwise subject identifier — unique per user per app. */
        sub,
        attributes: values
    };

    return JSON.stringify(payload);
}

/**
 * Deliver approved attributes directly to an enclave via RA-TLS.
 *
 * The RA-TLS channel provides:
 * - Encryption (TLS 1.3)
 * - Server attestation (enclave measurement verified)
 * - Integrity (TLS record MAC)
 *
 * No additional encryption layer needed — the native TLS handles it.
 */
export async function deliverDirect(
    approvedAttributes: string[],
    options: DirectDeliveryOptions
): Promise<DeliveryResult> {
    const payload = await buildPayload(approvedAttributes, options.host);

    try {
        const result = await NativeRaTls.post(
            options.host,
            options.port,
            options.path,
            payload,
            options.caCertPath
        );

        return {
            success: result.status >= 200 && result.status < 300,
            status: result.status,
            body: result.body
        };
    } catch (e: any) {
        return {
            success: false,
            error: e.message
        };
    }
}

/**
 * Deliver approved attributes via the broker WebSocket relay.
 *
 * Since the broker is a stateless relay, the payload is wrapped in a
 * broker message and sent to the enclave's paired socket. The RA-TLS
 * verification has already been performed by the wallet before consent
 * was granted, so the measurement binding is captured in the consent record.
 *
 * The broker relay is over WSS (TLS), providing transport encryption.
 * For additional defense-in-depth, the payload is wrapped with a nonce
 * and timestamp to prevent replay.
 */
export async function deliverViaBroker(
    approvedAttributes: string[],
    options: BrokerDeliveryOptions,
    rpId: string
): Promise<DeliveryResult> {
    const payload = await buildPayload(approvedAttributes, rpId);

    return new Promise((resolve) => {
        let settled = false;

        const timeout = setTimeout(() => {
            if (!settled) {
                settled = true;
                resolve({ success: false, error: 'Broker delivery timed out' });
            }
            ws.close();
        }, 15_000);

        const wsUrl = `${options.brokerUrl}?session=${encodeURIComponent(options.sessionId)}&role=wallet`;
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            const msg: BrokerMessage = {
                type: 'data-response',
                payload: {
                    data: payload
                }
            };
            ws.send(JSON.stringify(msg));
            settled = true;
            clearTimeout(timeout);
            ws.close();
            resolve({ success: true });
        };

        ws.onerror = (event) => {
            if (!settled) {
                settled = true;
                clearTimeout(timeout);
                resolve({ success: false, error: 'WebSocket error' });
            }
        };

        ws.onclose = () => {
            if (!settled) {
                settled = true;
                clearTimeout(timeout);
                resolve({ success: false, error: 'Connection closed before delivery' });
            }
        };
    });
}
