// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Tests for the attested-dependency decoder and the approval cache.
 *
 * The decoder is cross-checked against the SAME canonical byte vector produced by
 * the Go SDK, the Rust SDK, and the enclave runtime — proving all four
 * implementations agree on the wire format.
 */

// Mock storage (in-memory), as the other store tests do.
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

import {
    decodeDependencySet,
    dependenciesFromCustomOids,
    dependencyIdentity,
    OID_ATTESTED_DEPENDENCY_SET,
} from '@/services/dependencies';
import { useDependencyApprovalsStore } from '@/stores/dependency-approvals';

// The exact encoding the Go SDK / Rust SDK / enclave runtime produce for the
// shared sample (see enclave-os-common dependencies.rs GO_ENCODE_HEX).
const SHARED_VECTOR_HEX =
    '000000010000000f636f6e666964656e7469616c2d616900000002000000087367783a616162620000000c7464783a31313a32323a33330000000200000015312e332e362e312e342e312e36353233302e332e3200000002dead00000015312e332e362e312e342e312e36353233302e332e360000000261690000000430306666';

function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

describe('dependency decoder', () => {
    it('decodes the shared cross-language vector', () => {
        const deps = decodeDependencySet(hexToBytes(SHARED_VECTOR_HEX));
        expect(deps).toHaveLength(1);
        const d = deps[0];
        expect(d.appId).toBe('confidential-ai');
        expect(d.measurements).toEqual(['sgx:aabb', 'tdx:11:22:33']);
        expect(d.requiredOids).toEqual([
            { oid: '1.3.6.1.4.1.65230.3.2', valueHex: 'dead' },
            { oid: '1.3.6.1.4.1.65230.3.6', valueHex: '6169' }, // "ai"
        ]);
        expect(d.foldedIdentity).toBe('00ff');
    });

    it('reads the set from custom OIDs and ignores a malformed extension', () => {
        expect(
            dependenciesFromCustomOids([{ oid: OID_ATTESTED_DEPENDENCY_SET, value_hex: SHARED_VECTOR_HEX }])
        ).toHaveLength(1);
        expect(dependenciesFromCustomOids([{ oid: OID_ATTESTED_DEPENDENCY_SET, value_hex: 'zz' }])).toEqual([]);
        expect(dependenciesFromCustomOids([])).toEqual([]);
    });

    it('prefers the folded identity for the cache key', () => {
        const withFold = { appId: 'a', measurements: ['sgx:11'], requiredOids: [], foldedIdentity: 'ABCD' };
        expect(dependencyIdentity(withFold)).toBe('abcd');
        const leaf = { appId: 'a', measurements: ['sgx:11'], requiredOids: [], foldedIdentity: '' };
        expect(dependencyIdentity(leaf)).toContain('leaf:');
    });
});

describe('dependency approvals store', () => {
    beforeEach(() => useDependencyApprovalsStore.setState({ approvals: {} }));

    const dep = { appId: 'confidential-ai', measurements: ['sgx:11'], requiredOids: [], foldedIdentity: 'ff00' };

    it('caches an approval and reuses it across parent apps', () => {
        const s = useDependencyApprovalsStore.getState();
        const identity = dependencyIdentity(dep);

        // Approved via Drive.
        s.record({ appId: dep.appId, identity, decision: 'approved', parentRpId: 'drive.privasys.org', now: 100 });
        expect(useDependencyApprovalsStore.getState().isApproved(dep.appId, identity)).toBe(true);

        // Chat pulls in the same dependency at the same identity → cache hit,
        // provenance merges rather than re-prompting.
        const evalChat = useDependencyApprovalsStore.getState().evaluate([dep]);
        expect(evalChat[0].status).toBe('approved');

        useDependencyApprovalsStore
            .getState()
            .record({ appId: dep.appId, identity, decision: 'approved', parentRpId: 'chat.privasys.org', now: 200 });
        const rec = useDependencyApprovalsStore.getState().get(dep.appId, identity)!;
        expect(rec.usedBy.sort()).toEqual(['chat.privasys.org', 'drive.privasys.org']);
        expect(rec.firstSeen).toBe(100);
        expect(rec.lastSeen).toBe(200);
    });

    it('remembers a denial so the flow can remind the user', () => {
        const s = useDependencyApprovalsStore.getState();
        const identity = dependencyIdentity(dep);
        s.record({ appId: dep.appId, identity, decision: 'denied', parentRpId: 'drive.privasys.org', now: 1 });

        const decisions = useDependencyApprovalsStore.getState().evaluate([dep]);
        expect(decisions[0].status).toBe('denied');
        expect(decisions[0].previouslyDenied).toBe(true);
    });

    it('classifies a never-seen dependency as new', () => {
        const decisions = useDependencyApprovalsStore.getState().evaluate([dep]);
        expect(decisions[0].status).toBe('new');
    });

    it('revokes an approval', () => {
        const identity = dependencyIdentity(dep);
        const s = useDependencyApprovalsStore.getState();
        s.record({ appId: dep.appId, identity, decision: 'approved', parentRpId: 'drive.privasys.org' });
        useDependencyApprovalsStore.getState().revoke(dep.appId, identity);
        expect(useDependencyApprovalsStore.getState().get(dep.appId, identity)).toBeUndefined();
    });
});
