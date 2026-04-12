// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Smoke tests for consent store and consent service — standing consent,
 * consent records, attribute value retrieval, and per-app sub in data payloads.
 */

// Mock storage
jest.mock('@/utils/storage', () => {
    const store: Record<string, string> = {};
    return {
        getItemAsync: jest.fn(async (key: string) => store[key] ?? null),
        setItemAsync: jest.fn(async (key: string, value: string) => {
            store[key] = value;
        }),
        deleteItemAsync: jest.fn(async (key: string) => {
            delete store[key];
        }),
    };
});

// Mock NativeKeys
jest.mock('../../modules/native-keys/src/index', () => ({
    getPublicKey: jest.fn().mockResolvedValue({
        publicKey: 'BAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
        keyId: 'privasys-wallet-default',
        hardwareBacked: false,
    }),
}));

// Mock NativeRaTls
jest.mock('../../modules/native-ratls/src/index', () => ({
    post: jest.fn().mockResolvedValue({ status: 200, body: '{"ok":true}' }),
}));

// Mock expo-crypto
jest.mock('expo-crypto', () => ({
    getRandomBytesAsync: jest.fn().mockResolvedValue(new Uint8Array(16).fill(0xaa)),
    randomUUID: jest.fn().mockReturnValue('mock-uuid'),
    digestStringAsync: jest.fn().mockImplementation(
        async (_algo: string, input: string) => {
            // FNV-1a inspired deterministic hash
            let h = 0x811c9dc5;
            for (let i = 0; i < input.length; i++) {
                h ^= input.charCodeAt(i);
                h = Math.imul(h, 0x01000193);
            }
            const u = h >>> 0;
            const hex = u.toString(16).padStart(8, '0');
            return hex.repeat(8);
        }
    ),
    CryptoDigestAlgorithm: { SHA256: 'SHA-256' },
}));

import { useConsentStore } from '@/stores/consent';
import { useProfileStore } from '@/stores/profile';
import {
    checkStandingConsent,
    getAttributeValues,
    recordConsent,
    type DataRequest,
} from '@/services/consent';

// Reset stores between tests
beforeEach(() => {
    useConsentStore.setState({
        records: [],
        standingConsents: [],
        receipts: [],
    });
    useProfileStore.setState({ profile: null });
});

const makeRequest = (overrides?: Partial<DataRequest>): DataRequest => ({
    rpId: 'app1.privasys.org',
    origin: 'https://app1.privasys.org',
    appName: 'Test App',
    sessionId: 'session-123',
    requestedAttributes: ['displayName', 'email'],
    purpose: 'Test',
    teeType: 'sgx',
    enclaveMeasurement: 'mrenclave-abc',
    codeHash: 'codehash-123',
    ...overrides,
});

describe('consent store', () => {
    it('adds and retrieves consent records', () => {
        const store = useConsentStore.getState();
        store.addRecord({
            id: 'rec-1',
            rpId: 'app1.privasys.org',
            origin: 'https://app1.privasys.org',
            appName: 'Test App',
            requestedAttributes: ['email'],
            approvedAttributes: ['email'],
            deniedAttributes: [],
            decision: 'approved',
            persistent: false,
            teeType: 'sgx',
            enclaveMeasurement: 'mrenclave-abc',
            codeHash: 'codehash-123',
            consentedAt: Date.now() / 1000,
            expiresAt: 0,
        });

        const records = useConsentStore.getState().getRecordsForApp('app1.privasys.org');
        expect(records).toHaveLength(1);
        expect(records[0].decision).toBe('approved');
    });

    it('sets and retrieves standing consent with matching measurement', () => {
        const store = useConsentStore.getState();
        store.setStandingConsent({
            rpId: 'app1.privasys.org',
            attributes: ['email', 'displayName'],
            enclaveMeasurement: 'mrenclave-abc',
            codeHash: 'codehash-123',
            grantedAt: Date.now() / 1000,
        });

        const standing = store.getStandingConsent('app1.privasys.org', 'mrenclave-abc', 'codehash-123');
        expect(standing).not.toBeUndefined();
        expect(standing!.attributes).toContain('email');

        // Different measurement → no match
        const noMatch = store.getStandingConsent('app1.privasys.org', 'mrenclave-DIFFERENT', 'codehash-123');
        expect(noMatch).toBeUndefined();
    });

    it('revokes standing consent', () => {
        const store = useConsentStore.getState();
        store.setStandingConsent({
            rpId: 'app1.privasys.org',
            attributes: ['email'],
            enclaveMeasurement: 'mrenclave-abc',
            codeHash: 'codehash-123',
            grantedAt: Date.now() / 1000,
        });

        store.removeStandingConsent('app1.privasys.org');
        const standing = store.getStandingConsent('app1.privasys.org', 'mrenclave-abc', 'codehash-123');
        expect(standing).toBeUndefined();
    });
});

describe('consent service', () => {
    describe('checkStandingConsent', () => {
        it('returns standing consent when all attributes are covered', () => {
            useConsentStore.getState().setStandingConsent({
                rpId: 'app1.privasys.org',
                attributes: ['displayName', 'email', 'locale'],
                enclaveMeasurement: 'mrenclave-abc',
                codeHash: 'codehash-123',
                grantedAt: Date.now() / 1000,
            });

            const result = checkStandingConsent(makeRequest());
            expect(result).not.toBeUndefined();
        });

        it('returns undefined when requested attributes exceed standing consent', () => {
            useConsentStore.getState().setStandingConsent({
                rpId: 'app1.privasys.org',
                attributes: ['displayName'], // email not covered
                enclaveMeasurement: 'mrenclave-abc',
                codeHash: 'codehash-123',
                grantedAt: Date.now() / 1000,
            });

            const result = checkStandingConsent(makeRequest());
            expect(result).toBeUndefined();
        });
    });

    describe('getAttributeValues', () => {
        it('returns profile field values', () => {
            useProfileStore.getState().createProfile({
                displayName: 'Alice',
                email: 'alice@example.com',
                avatarUri: '',
                locale: 'en',
                did: 'did:key:z123',
                canonicalDid: 'did:web:privasys.id:users:alice',
                pairwiseSeed: 'ab'.repeat(32),
                linkedProviders: [],
                attributes: [],
            });

            const values = getAttributeValues(['displayName', 'email', 'locale', 'missing']);
            expect(values['displayName']).toBe('Alice');
            expect(values['email']).toBe('alice@example.com');
            expect(values['locale']).toBe('en');
            expect(values['missing']).toBeUndefined();
        });

        it('returns extended attribute values', () => {
            useProfileStore.getState().createProfile({
                displayName: 'Alice',
                email: '',
                avatarUri: '',
                locale: '',
                did: 'did:key:z123',
                canonicalDid: 'did:web:privasys.id:users:alice',
                pairwiseSeed: 'ab'.repeat(32),
                linkedProviders: [],
                attributes: [
                    { key: 'company', label: 'Company', value: 'Privasys', source: 'manual', verified: false },
                ],
            });

            const values = getAttributeValues(['company']);
            expect(values['company']).toBe('Privasys');
        });
    });

    describe('recordConsent', () => {
        it('records an approved consent decision', async () => {
            const request = makeRequest();
            const record = await recordConsent(request, ['displayName', 'email'], false);

            expect(record.decision).toBe('approved');
            expect(record.approvedAttributes).toEqual(['displayName', 'email']);
            expect(record.deniedAttributes).toEqual([]);

            const stored = useConsentStore.getState().records;
            expect(stored).toHaveLength(1);
        });

        it('records a denied consent decision', async () => {
            const record = await recordConsent(makeRequest(), [], false);
            expect(record.decision).toBe('denied');
        });

        it('records a partial consent decision', async () => {
            const record = await recordConsent(makeRequest(), ['displayName'], false);
            expect(record.decision).toBe('partial');
            expect(record.approvedAttributes).toEqual(['displayName']);
            expect(record.deniedAttributes).toEqual(['email']);
        });

        it('creates standing consent when persistent=true', async () => {
            await recordConsent(makeRequest(), ['displayName', 'email'], true);

            const standing = useConsentStore.getState().getStandingConsent(
                'app1.privasys.org',
                'mrenclave-abc',
                'codehash-123'
            );
            expect(standing).not.toBeUndefined();
            expect(standing!.attributes).toEqual(['displayName', 'email']);
        });
    });
});

describe('data-transit buildPayload', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { buildPayload } = require('@/services/data-transit') as typeof import('@/services/data-transit');

    it('includes per-app derived sub in payload', async () => {
        useProfileStore.getState().createProfile({
            displayName: 'Alice',
            email: 'alice@example.com',
            avatarUri: '',
            locale: '',
            did: 'did:key:z123',
            canonicalDid: 'did:web:privasys.id:users:alice',
            pairwiseSeed: 'ab'.repeat(32),
            linkedProviders: [],
            attributes: [],
        });

        const json = await buildPayload(['displayName', 'email'], 'app1.privasys.org');
        const payload = JSON.parse(json);

        expect(payload.version).toBe(1);
        expect(payload.sub).toBeDefined();
        expect(typeof payload.sub).toBe('string');
        expect(payload.sub.length).toBeGreaterThan(0);
        expect(payload.attributes.displayName).toBe('Alice');
        expect(payload.attributes.email).toBe('alice@example.com');
        expect(payload.nonce).toBe('mock-uuid');
    });

    it('produces different subs for different rpIds', async () => {
        useProfileStore.getState().createProfile({
            displayName: 'Alice',
            email: '',
            avatarUri: '',
            locale: '',
            did: 'did:key:z123',
            canonicalDid: 'did:web:privasys.id:users:alice',
            pairwiseSeed: 'ab'.repeat(32),
            linkedProviders: [],
            attributes: [],
        });

        const p1 = JSON.parse(await buildPayload([], 'app1.privasys.org'));
        const p2 = JSON.parse(await buildPayload([], 'app2.privasys.org'));

        expect(p1.sub).not.toBe(p2.sub);
    });
});
