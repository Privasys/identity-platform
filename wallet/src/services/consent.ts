// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Consent request handling — processes data sharing requests from enclaves.
 *
 * Flow:
 * 1. Enclave app sends data request via broker push notification
 * 2. Wallet checks for standing consent (auto-approve if enclave hasn't changed)
 * 3. If no standing consent, shows consent UI to user
 * 4. Approved attributes are encrypted to the enclave's RA-TLS public key
 * 5. Encrypted data sent back to enclave via broker
 * 6. Enclave processes data, returns computation receipt
 * 7. Wallet stores consent record + receipt
 */

import * as Crypto from 'expo-crypto';

import { useConsentStore, type ConsentRecord, type StandingConsent, type ComputationReceipt } from '@/stores/consent';
import { useProfileStore } from '@/stores/profile';

/** A data request from an enclave app. */
export interface DataRequest {
    /** RP ID of the requesting enclave. */
    rpId: string;
    /** Origin of the enclave. */
    origin: string;
    /** Display name of the app. */
    appName?: string;
    /** Session ID for the broker relay. */
    sessionId: string;
    /** Attribute keys being requested. */
    requestedAttributes: string[];
    /** Purpose/reason for the data request (displayed to user). */
    purpose?: string;
    /** TEE type. */
    teeType: 'sgx' | 'tdx';
    /** Enclave measurement (MRENCLAVE or MRTD). */
    enclaveMeasurement: string;
    /** Code hash. */
    codeHash: string;
}

/** Result of processing a data request. */
export interface ConsentResult {
    /** Whether the user approved (fully or partially). */
    approved: boolean;
    /** The attributes that were approved for sharing. */
    approvedAttributes: string[];
    /** The consent record stored locally. */
    record: ConsentRecord;
}

/** Generate a unique consent record ID. */
async function generateConsentId(): Promise<string> {
    const bytes = await Crypto.getRandomBytesAsync(16);
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Check if a data request can be auto-approved via standing consent.
 * Standing consent is valid only if the enclave measurement and code hash
 * haven't changed since the consent was granted.
 */
export function checkStandingConsent(request: DataRequest): StandingConsent | undefined {
    const store = useConsentStore.getState();
    const standing = store.getStandingConsent(
        request.rpId,
        request.enclaveMeasurement,
        request.codeHash
    );

    if (!standing) return undefined;

    // Check that all requested attributes are covered by standing consent
    const allCovered = request.requestedAttributes.every((attr) =>
        standing.attributes.includes(attr)
    );

    return allCovered ? standing : undefined;
}

/**
 * Get the attribute values from the profile for the approved attributes.
 * Returns a map of attribute key → value.
 */
export function getAttributeValues(
    attributeKeys: string[]
): Record<string, string> {
    const profile = useProfileStore.getState().profile;
    if (!profile) return {};

    const values: Record<string, string> = {};

    for (const key of attributeKeys) {
        // Check direct profile fields
        switch (key) {
            case 'displayName':
                if (profile.displayName) values[key] = profile.displayName;
                break;
            case 'email':
                if (profile.email) values[key] = profile.email;
                break;
            case 'avatarUri':
                if (profile.avatarUri) values[key] = profile.avatarUri;
                break;
            case 'locale':
                if (profile.locale) values[key] = profile.locale;
                break;
            case 'did':
                if (profile.did) values[key] = profile.did;
                break;
            default: {
                // Check extended attributes
                const attr = profile.attributes.find((a) => a.key === key);
                if (attr) values[key] = attr.value;
            }
        }
    }

    return values;
}

/**
 * Record a consent decision (called after user approves/denies in the UI).
 */
export async function recordConsent(
    request: DataRequest,
    approvedAttributes: string[],
    persistent: boolean
): Promise<ConsentRecord> {
    const store = useConsentStore.getState();
    const deniedAttributes = request.requestedAttributes.filter(
        (a) => !approvedAttributes.includes(a)
    );

    let decision: ConsentRecord['decision'];
    if (approvedAttributes.length === 0) {
        decision = 'denied';
    } else if (deniedAttributes.length === 0) {
        decision = 'approved';
    } else {
        decision = 'partial';
    }

    const record: ConsentRecord = {
        id: await generateConsentId(),
        rpId: request.rpId,
        origin: request.origin,
        appName: request.appName,
        requestedAttributes: request.requestedAttributes,
        approvedAttributes,
        deniedAttributes,
        decision,
        persistent,
        teeType: request.teeType,
        enclaveMeasurement: request.enclaveMeasurement,
        codeHash: request.codeHash,
        consentedAt: Math.floor(Date.now() / 1000),
        expiresAt: 0 // Per-request by default
    };

    store.addRecord(record);

    // Set standing consent if user opted in
    if (persistent && approvedAttributes.length > 0) {
        store.setStandingConsent({
            rpId: request.rpId,
            attributes: approvedAttributes,
            enclaveMeasurement: request.enclaveMeasurement,
            codeHash: request.codeHash,
            grantedAt: record.consentedAt
        });
    }

    return record;
}

/**
 * Store a computation receipt from an enclave.
 */
export function storeReceipt(receipt: ComputationReceipt): void {
    useConsentStore.getState().addReceipt(receipt);
}
