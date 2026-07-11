// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Field-level diff between a previously trusted attestation record and a
 * freshly verified one, so the "App Changed" wake can tell the user WHAT
 * changed instead of showing a generic warning.
 *
 * The taxonomy mirrors the session-relay wake semantics (crypto-contract
 * §8.5/§8.7): an app code/config change (workload OIDs 3.1/3.2) and a
 * platform change (MRENCLAVE/MRTD) are different events with different risk
 * stories. The common case, a developer shipping a new version, should read
 * as routine rather than alarming; a platform change should be called out as
 * such. A benign enclave restart never reaches this screen at all: the
 * vault-backed identity key keeps enc_pub stable, so the silent rebind
 * succeeds and no ceremony runs.
 */

import type { AttestationResult } from '../../modules/native-ratls/src/NativeRaTls.types';
import type { TrustedApp } from '@/stores/trusted-apps';

export interface AttestationFieldChange {
    field: 'platform' | 'code' | 'config';
    /** Row label, e.g. 'Platform (MRTD)'. */
    label: string;
    /** Hex value recorded at the last verification (undefined if none was). */
    previous?: string;
    /** Hex value in the fresh attestation (undefined if absent). */
    current?: string;
}

export type AttestationChangeKind =
    | 'app-update'
    | 'platform-update'
    | 'app-and-platform-update';

export interface AttestationDiff {
    kind: AttestationChangeKind;
    changes: AttestationFieldChange[];
    /** One-sentence human summary for the banner. */
    summary: string;
}

const SUMMARIES: Record<AttestationChangeKind, string> = {
    'app-update':
        'This app’s code has changed since you last verified it, usually a routine update by its developer. The secure enclave it runs in is the same.',
    'platform-update':
        'The secure enclave running this app has been upgraded. The app’s own code is the same as when you last verified it.',
    'app-and-platform-update':
        'Both this app’s code and the secure enclave running it have changed since you last verified it.',
};

function changed(previous?: string, current?: string): boolean {
    return (previous ?? '') !== (current ?? '');
}

/**
 * Compare the trusted record against a fresh attestation, using the SAME raw
 * fields `isAttestationMatch` compares (and the trust rows persist), so this
 * diff explains exactly the mismatch that routed the flow to the
 * attestation-changed step. Returns null when nothing differs.
 */
export function diffTrustedAttestation(
    trusted: TrustedApp,
    att: AttestationResult
): AttestationDiff | null {
    const changes: AttestationFieldChange[] = [];

    // Platform measurements. Compare both axes independently so a TEE-family
    // migration (SGX -> TDX) surfaces as two rows instead of hiding one side.
    if (changed(trusted.mrenclave, att.mrenclave)) {
        changes.push({
            field: 'platform',
            label: 'Platform (MRENCLAVE)',
            previous: trusted.mrenclave,
            current: att.mrenclave,
        });
    }
    if (changed(trusted.mrtd, att.mrtd)) {
        changes.push({
            field: 'platform',
            label: 'Platform (MRTD)',
            previous: trusted.mrtd,
            current: att.mrtd,
        });
    }

    if (changed(trusted.codeHash, att.workload_code_hash)) {
        changes.push({
            field: 'code',
            label: 'Application code',
            previous: trusted.codeHash,
            current: att.workload_code_hash,
        });
    }
    if (changed(trusted.configRoot, att.workload_config_merkle_root)) {
        changes.push({
            field: 'config',
            label: 'Application configuration',
            previous: trusted.configRoot,
            current: att.workload_config_merkle_root,
        });
    }

    if (changes.length === 0) return null;

    const platformMoved = changes.some((c) => c.field === 'platform');
    const workloadMoved = changes.some((c) => c.field !== 'platform');
    const kind: AttestationChangeKind = platformMoved
        ? workloadMoved
            ? 'app-and-platform-update'
            : 'platform-update'
        : 'app-update';

    return { kind, changes, summary: SUMMARIES[kind] };
}
