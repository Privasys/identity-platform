// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

import { DRIVE_ID } from './drive-files';
import { openSealedNotification } from './notify-seal';
import { useDriveNotificationsStore } from '../stores/drive-notifications';

/** Whether a notification is a Drive share request or decision. */
export function isDriveShare(data: Record<string, unknown> | undefined): boolean {
    return data?.type === 'share-request' || data?.type === 'share-decision';
}

/**
 * File a Drive share notification into its store: unseal the payload, update
 * the attribute referential and the request and decision lists. Returns true
 * when `data` was a Drive share notification.
 */
export async function fileDriveNotification(data: Record<string, unknown>): Promise<boolean> {
    if (!isDriveShare(data)) return false;
    const type = String(data.type);
    const sealed = typeof data.sealed === 'string' ? data.sealed : '';
    if (!sealed) return true; // unsealed generic push: nothing to file
    const payload = await openSealedNotification(sealed, type);
    if (!payload) return true;
    const store = useDriveNotificationsStore.getState();
    await store.hydrate();
    if (type === 'share-request') {
        store.addRequest(
            {
                requestId: String(payload.request_id ?? ''),
                tenantId: String(payload.tenant_id ?? ''),
                nodeId: String(payload.node_id ?? ''),
                nodeName: String(payload.node_name ?? ''),
                requesterSub: String(payload.requester_sub ?? ''),
                scope: Array.isArray(payload.scope) ? payload.scope.map(String) : ['read'],
            },
            (payload.attributes as Record<string, string>) ?? {},
            typeof data.app_id === 'string' ? data.app_id : undefined
        );
    } else {
        store.addDecision({
            requestId: String(payload.request_id ?? ''),
            nodeName: String(payload.node_name ?? ''),
            status: payload.status === 'approved' ? 'approved' : 'denied',
            tenantId: DRIVE_ID.test(String(payload.tenant_id ?? '')) ? String(payload.tenant_id) : undefined,
            nodeId: DRIVE_ID.test(String(payload.node_id ?? '')) ? String(payload.node_id) : undefined,
        });
    }
    return true;
}
