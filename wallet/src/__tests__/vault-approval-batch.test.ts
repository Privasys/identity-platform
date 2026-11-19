// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
    computeVaultBatchId,
    computeVaultOp,
    dashedAppId,
    describeVaultHandle,
    reachedEndOfList,
    VaultBatchRefused,
    verifyVaultBatch,
    type VaultBatchRefusal,
} from '@/services/vault-approval-batch';

interface VectorEntry {
    operation: string;
    handle: string;
    measurement_digest: string;
    policy_version: number;
    nonce: string;
    vault_op: string;
    context?: Record<string, string>;
}

const vector = JSON.parse(
    readFileSync(resolve(__dirname, '..', '..', '..', 'shared', 'vault-approval-batch-vectors.json'), 'utf8'),
) as { batch_id: string; exp: number; label: string; entries: VectorEntry[] };

/** The answer `batch/pending` gives for the shared vector. */
function answer() {
    return {
        batch_id: vector.batch_id,
        label: vector.label,
        exp: vector.exp,
        expires_at: vector.exp,
        options: { publicKey: { challenge: vector.batch_id, rpId: 'privasys.id', allowCredentials: [{ type: 'public-key', id: 'cred' }] } },
        entries: vector.entries.map((e) => ({ ...e })),
    };
}

/** An answer whose hashes are all self-consistent, so that only the rule under
 *  test can refuse it: what a dishonest server would have to send. */
function rebound(entries: VectorEntry[], label = vector.label, exp = vector.exp) {
    const bound = entries.map((e) => ({
        ...e,
        vault_op: computeVaultOp(e.handle, e.measurement_digest, e.policy_version, e.nonce, exp),
    }));
    const batchId = computeVaultBatchId(label, exp, bound.map((e) => ({ operation: e.operation, vaultOp: e.vault_op })));
    return { batch_id: batchId, label, exp, options: { publicKey: { challenge: batchId } }, entries: bound };
}

function refusal(requested: string, a: unknown): VaultBatchRefusal | 'accepted' {
    try {
        verifyVaultBatch(requested, a);
        return 'accepted';
    } catch (e) {
        if (e instanceof VaultBatchRefused) return e.reason;
        throw e;
    }
}

describe('the shared vector', () => {
    it('recomputes every vault_op the identity provider produced', () => {
        for (const e of vector.entries) {
            expect(computeVaultOp(e.handle, e.measurement_digest, e.policy_version, e.nonce, vector.exp)).toBe(e.vault_op);
        }
    });

    it('recomputes the batch id the identity provider produced', () => {
        const entries = vector.entries.map((e) => ({ operation: e.operation, vaultOp: e.vault_op }));
        expect(computeVaultBatchId(vector.label, vector.exp, entries)).toBe(vector.batch_id);
    });

    it('is accepted, in order, with the recomputed challenge', () => {
        const batch = verifyVaultBatch(vector.batch_id, answer());
        expect(batch.options.publicKey.challenge).toBe(vector.batch_id);
        expect(batch.entries.map((e) => e.handle)).toEqual(vector.entries.map((e) => e.handle));
    });
});

describe('a list that does not hash to the challenge is refused', () => {
    const tamper = (change: (a: ReturnType<typeof answer>) => void) => {
        const a = answer();
        change(a);
        return refusal(vector.batch_id, a);
    };

    it('a swapped handle', () => {
        expect(tamper((a) => { a.entries[2].handle = 'apps.privasys.org/cccc/storage-kek/v1'; })).toBe('entry');
    });
    it('a changed measurement', () => {
        expect(tamper((a) => { a.entries[1].measurement_digest = 'a'.repeat(64); })).toBe('entry');
    });
    it('a changed policy version', () => {
        expect(tamper((a) => { a.entries[0].policy_version = 4; })).toBe('entry');
    });
    it('a changed nonce', () => {
        expect(tamper((a) => { a.entries[0].nonce = 'nonce-9'; })).toBe('entry');
    });
    it('a changed vault_op', () => {
        expect(tamper((a) => { a.entries[0].vault_op = a.entries[1].vault_op; })).toBe('entry');
    });
    it('a dropped entry', () => {
        expect(tamper((a) => { a.entries.pop(); })).toBe('binding');
    });
    it('a changed label', () => {
        expect(tamper((a) => { a.label = 'Routine maintenance'; })).toBe('binding');
    });
    it('a changed expiry', () => {
        expect(tamper((a) => { a.exp += 60; })).toBe('entry');
    });
    it('a changed operation', () => {
        expect(tamper((a) => { a.entries[1].operation = 'app-policy'; })).toBe('malformed');
    });
    it('a reordered list', () => {
        expect(tamper((a) => { a.entries.reverse(); })).toBe('order');
    });
    it('a challenge other than the list', () => {
        expect(tamper((a) => { a.options.publicKey.challenge = 'A'.repeat(43); })).toBe('challenge');
    });
    it('an answer for another batch', () => {
        expect(refusal('A'.repeat(43), answer())).toBe('binding');
    });
});

describe('a self-consistent list is still refused when', () => {
    const entries = () => vector.entries.map((e) => ({ ...e }));

    it('it is out of canonical order', () => {
        const a = rebound(entries().reverse());
        expect(refusal(a.batch_id, a)).toBe('order');
    });
    it('it names an entry twice', () => {
        const list = entries();
        const a = rebound([list[0], list[1], list[1]]);
        expect(refusal(a.batch_id, a)).toBe('order');
    });
    it.each(['export', 'policy-update', 'app-recovery', ''])('it asks for %j', (operation) => {
        const list = entries();
        list[1].operation = operation;
        const a = rebound(list);
        expect(refusal(a.batch_id, a)).toBe('operation');
    });
    it('an app policy names something other than an app policy', () => {
        const list = entries();
        list[1].operation = 'app-policy';
        const a = rebound(list);
        expect(refusal(a.batch_id, a)).toBe('malformed');
    });
    it('it holds more than 32 entries', () => {
        const many = Array.from({ length: 33 }, (_, i) => ({
            ...vector.entries[1],
            handle: `apps.privasys.org/bbbb/k${String(i).padStart(2, '0')}`,
        }));
        const a = rebound(many);
        expect(refusal(a.batch_id, a)).toBe('malformed');
    });
    it('it is empty', () => {
        const a = rebound([]);
        expect(refusal(a.batch_id, a)).toBe('malformed');
    });
    it.each(['two\nlines', ' padded', 'hidden\u202emark', 'x'.repeat(121)])('the label is %j', (label) => {
        const a = rebound(entries(), label);
        expect(refusal(a.batch_id, a)).toBe('malformed');
    });
    it('a handle holds a line break', () => {
        const list = entries();
        list[2].handle = 'apps.privasys.org/bbbb/storage-kek/v1\npromote x';
        const a = rebound(list);
        expect(refusal(a.batch_id, a)).toBe('malformed');
    });
    it('a measurement is not lowercase hex', () => {
        const list = entries();
        list[0].measurement_digest = 'A'.repeat(64);
        const a = rebound(list);
        expect(refusal(a.batch_id, a)).toBe('malformed');
    });
    it('a policy version is too large to be exact', () => {
        const list = entries();
        list[0].policy_version = 2 ** 53;
        const a = rebound(list);
        expect(refusal(a.batch_id, a)).toBe('malformed');
    });
});

describe('what reaches the card', () => {
    it('carries nothing of the initiator-written context', () => {
        const a = answer();
        a.entries[0].context = { app_name: 'Payroll', summary: 'Nothing to see' };
        const batch = verifyVaultBatch(vector.batch_id, a);
        expect(JSON.stringify(batch)).not.toContain('Payroll');
        expect(JSON.stringify(batch)).not.toContain('Nothing to see');
    });

    it('sorts by UTF-8 bytes, as the identity provider does', () => {
        // U+1F600 comes first in UTF-16 units, but after U+FF5E in UTF-8 bytes.
        const base = vector.entries[1];
        const a = rebound([
            { ...base, handle: 'apps.privasys.org/\uff5e' },
            { ...base, handle: 'apps.privasys.org/\u{1f600}' },
        ]);
        expect(refusal(a.batch_id, a)).toBe('accepted');
    });
});

describe('describeVaultHandle', () => {
    const app = 'ab'.repeat(16);

    it.each([
        [`app:${app}:policy`, { kind: 'policy', appId: app }],
        [`apps.privasys.org/${app}/storage-kek/v1`, { kind: 'storage', appId: app }],
        [`apps.privasys.org/${app}/registry-cred/default`, { kind: 'registry', appId: app }],
        [`apps.privasys.org/${app}/session-encpub/00aa/e12`, { kind: 'session', appId: app }],
        [`apps.privasys.org/${app}/data/owner/mek/1`, { kind: 'data', appId: app }],
        [`apps.privasys.org/${app}/manager/data/v1`, { kind: 'host', enclaveId: app }],
    ])('%s', (handle, want) => {
        expect(describeVaultHandle(handle)).toEqual(want);
    });

    it.each(['app:drive:policy', 'apps.privasys.org/drive/storage-kek/v1', `example.org/${app}/storage-kek/v1`, `apps.privasys.org/${app}/new-kind/v1`])(
        'names no app for %s',
        (handle) => {
            expect(describeVaultHandle(handle)).toEqual({ kind: 'other' });
        },
    );

    it('writes an app id the way the control plane does', () => {
        expect(dashedAppId('0123456789abcdef0123456789abcdef')).toBe('01234567-89ab-cdef-0123-456789abcdef');
    });
});

describe('reachedEndOfList', () => {
    it('is false before the first layout', () => {
        expect(reachedEndOfList({ offsetY: 0, viewportHeight: 0, contentHeight: 0 })).toBe(false);
        expect(reachedEndOfList({ offsetY: 0, viewportHeight: 600, contentHeight: 0 })).toBe(false);
    });
    it('is true at once for a list that fits', () => {
        expect(reachedEndOfList({ offsetY: 0, viewportHeight: 600, contentHeight: 400 })).toBe(true);
    });
    it('is false part of the way down a long list', () => {
        expect(reachedEndOfList({ offsetY: 900, viewportHeight: 600, contentHeight: 2000 })).toBe(false);
    });
    it('is true at the end of a long list', () => {
        expect(reachedEndOfList({ offsetY: 1400, viewportHeight: 600, contentHeight: 2000 })).toBe(true);
    });
});
