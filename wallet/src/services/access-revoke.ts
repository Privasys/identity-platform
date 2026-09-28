// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Ending standing access, one grant or several.
 *
 * One grant is what the detail screen ends. Several is what "Disconnect Gmail",
 * "Disconnect this account" and "Remove everything for this app" end: each is
 * the same revoke, grant by grant, at the service that holds it. The wallet
 * never marks a grant ended on the strength of a tap, only once its service
 * has said so, and one service that cannot be reached leaves the others' ends
 * standing and its own grant listed.
 */

import { resolveApp } from '@/services/app-resolve';
import { revokeAtCallingApp, revokeCapability, serviceUrlHost } from '@/services/capabilities';
import { syncGrantsIndex } from '@/services/grants-index';
import { forgetSetup } from '@/services/setup-keep';
import { capabilityKey, useCapabilitiesStore, type CapabilityRecord } from '@/stores/capabilities';
import { isLive } from '@/utils/access-rows';

/**
 * Where a grant lives: the host its capability was minted at, or the service
 * resolved again by identity. Never a hostname remembered from the approval.
 */
export async function hostOf(r: CapabilityRecord): Promise<string> {
    if (r.serviceUrl) return serviceUrlHost(r.serviceUrl);
    const resolved = await resolveApp(r.resourceAppId);
    if (!resolved?.hostname) throw new Error('the service could not be found');
    return resolved.hostname;
}

/**
 * Whether any OTHER live record on this phone uses the same account at the
 * same service and kind: another app the holder approved over it. Read at call
 * time, after the revoked one has been marked.
 */
export function accountStillUsed(revoked: CapabilityRecord, nowSeconds: number): boolean {
    const mine = capabilityKey(revoked);
    return useCapabilitiesStore
        .getState()
        .records.some(
            (r) =>
                capabilityKey(r) !== mine &&
                r.resourceAppId === revoked.resourceAppId &&
                r.kind === revoked.kind &&
                (r.account ?? '') === (revoked.account ?? '') &&
                isLive(r, nowSeconds),
        );
}

/**
 * End one grant. Throws, having changed nothing on this phone, when the
 * service did not confirm.
 */
export async function revokeRecord(record: CapabilityRecord, knownHost?: string): Promise<void> {
    if (!record.capabilityId) throw new Error('this grant has no id at its service');
    const host = knownHost || (await hostOf(record));
    await revokeCapability(host, record.capabilityId, record.serviceUrl);
    // Only now. The service has confirmed.
    useCapabilitiesStore.getState().markRevoked(capabilityKey(record));
    // The details this phone kept for that account go with the LAST live
    // grant over it, at the same moment the service destroys its own copy.
    // While another app is still approved over the account they stay: the
    // credential serves every app the holder approved.
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (record.setupProvided && !accountStillUsed(record, nowSeconds)) {
        await forgetSetup(record.resourceAppId, record.kind, record.account ?? '');
    }
    // Then the app that asked, so it stops saying "approved". After, not
    // before, and never instead.
    await revokeAtCallingApp({
        callingAppId: record.appId,
        capabilityId: record.capabilityId,
        resourceHost: host,
        resolve: resolveApp,
    });
}

export interface BulkOutcome {
    revoked: number;
    failed: { record: CapabilityRecord; error: unknown }[];
}

/**
 * End every live grant in the list, one at a time, each at its own service.
 * Never throws: what could not be ended is returned, and stays listed.
 */
export async function revokeRecords(records: CapabilityRecord[]): Promise<BulkOutcome> {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const out: BulkOutcome = { revoked: 0, failed: [] };
    for (const record of records) {
        if (!isLive(record, nowSeconds)) continue;
        try {
            await revokeRecord(record);
            out.revoked++;
        } catch (error) {
            console.warn(
                `[ACCESS] revoke failed for ${record.capabilityId}: ${error instanceof Error ? error.message : String(error)}`,
            );
            out.failed.push({ record, error });
        }
    }
    if (out.revoked > 0) void syncGrantsIndex();
    return out;
}
