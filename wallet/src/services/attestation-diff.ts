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
    /**
     * Translation KEY for the row label, e.g. 'attestation.rowPlatformMrtd'.
     * A key rather than a string because this record is built outside React
     * and may be held across a language change.
     */
    labelKey: string;
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
    /** Translation key for the one-sentence banner summary. */
    summaryKey: string;
}

const SUMMARY_KEYS: Record<AttestationChangeKind, string> = {
    'app-update': 'attestation.summaryAppUpdate',
    'platform-update': 'attestation.summaryPlatformUpdate',
    'app-and-platform-update': 'attestation.summaryAppAndPlatformUpdate',
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
            labelKey: 'attestation.rowPlatformMrenclave',
            previous: trusted.mrenclave,
            current: att.mrenclave,
        });
    }
    if (changed(trusted.mrtd, att.mrtd)) {
        changes.push({
            field: 'platform',
            labelKey: 'attestation.rowPlatformMrtd',
            previous: trusted.mrtd,
            current: att.mrtd,
        });
    }
    // RTMR1/RTMR2 move on a platform-runtime upgrade (kernel/initrd) even when
    // MRTD does not, and they rotate the session-relay enc_pub — so a change
    // here IS a platform upgrade to call out. Only diff when a previous value
    // was recorded: a legacy trust row predating RTMR tracking has none, and
    // an absent→present transition is us starting to track them, not a real
    // change (isAttestationMatch is lenient for the same reason).
    if (trusted.rtmr1 && changed(trusted.rtmr1, att.rtmr1)) {
        changes.push({
            field: 'platform',
            labelKey: 'attestation.rowPlatformRtmr1',
            previous: trusted.rtmr1,
            current: att.rtmr1,
        });
    }
    if (trusted.rtmr2 && changed(trusted.rtmr2, att.rtmr2)) {
        changes.push({
            field: 'platform',
            labelKey: 'attestation.rowPlatformRtmr2',
            previous: trusted.rtmr2,
            current: att.rtmr2,
        });
    }

    if (changed(trusted.codeHash, att.workload_code_hash)) {
        changes.push({
            field: 'code',
            labelKey: 'attestation.rowApplicationCode',
            previous: trusted.codeHash,
            current: att.workload_code_hash,
        });
    }
    if (changed(trusted.configRoot, att.workload_config_merkle_root)) {
        changes.push({
            field: 'config',
            labelKey: 'attestation.rowApplicationConfig',
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

    return { kind, changes, summaryKey: SUMMARY_KEYS[kind] };
}
