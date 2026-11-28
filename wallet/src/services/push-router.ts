// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * What a notification does, by its type. Some do silent work whenever they
 * arrive (a deletion notice, a notification cleared on another phone, an
 * update from another phone). The others open a screen or a link: on arrival
 * only for what the holder is waiting on (opensAtOnce), otherwise on a tap.
 */

import type { Router } from 'expo-router';
import { AppState, Linking } from 'react-native';

import { DELETION_PUSH_TYPES, handleDeletionPush } from './account-deletion-events';
import { APP_FORM_TYPE } from './app-form';
import { APP_MESSAGE_TYPE, appMessageLink, readAppMessage } from './app-message';
import { APPROVAL_TYPE } from './approval';
import { fetchAttributeApproval } from './attribute-approval-api';
import { DEFAULT_RELAY_HOST, fetchDescriptor } from './descriptor';
import { pullRelay } from './device-sync';
import { driveRouteFor } from './drive-files';
import { fileDriveNotification } from './drive-share-push';
import { dismissHere, DISMISS_TYPE, notificationAnswered } from './notification-dismiss';
import { openSealedNotification } from './notify-seal';
import { answerBindChallenge, carriesBindChallenge } from './push-bind';
import { getNotifications, opensAtOnce } from './push-notifications';
import { sweepTray } from './push-tray';
import { vaultBatchRouteName } from './vault-approval-batch';
import { dismissAppMessage, readMessage, useAppMessagesStore } from '../stores/app-messages';
import { useAppLockStore } from '../stores/app-lock';
import { useDriveNotificationsStore } from '../stores/drive-notifications';
import { useGuardianRequestsStore } from '../stores/guardian-requests';
import { useVaultApprovalsStore } from '../stores/vaultApprovals';
import { isRouteActive } from '../utils/active-route';

type Data = Record<string, unknown>;
type Handler = (data: Data, router: Router) => Promise<void> | void;

const text = (v: unknown): string => (typeof v === 'string' ? v : '');

/** Parse the broker's JSON-array-string host list ("[\"a\",\"b\"]") safely. */
function parseHostList(v: unknown): string[] | undefined {
    if (Array.isArray(v)) return v.filter((h): h is string => typeof h === 'string');
    if (typeof v !== 'string' || !v) return undefined;
    try {
        const arr = JSON.parse(v);
        return Array.isArray(arr) ? arr.filter((h): h is string => typeof h === 'string') : undefined;
    } catch {
        return undefined;
    }
}

/** Relay host for a broker URL (`wss://relay.privasys.org/relay` → host). */
function relayHostFrom(brokerUrl: unknown): string {
    try {
        return new URL(String(brokerUrl ?? '')).host || DEFAULT_RELAY_HOST;
    } catch {
        return DEFAULT_RELAY_HOST;
    }
}

/**
 * The connect screen's payload from an auth-request or a voucher-request
 * notification, or null when it is neither or is missing what it needs.
 */
export function authRequestPayload(data: Data): string | null {
    // Voucher-only: extend a LIVE session to an additional enclave with one
    // biometric, no sign-in ceremony. Needs the target host, the IdP session
    // row (sid) the browser is polling and a throwaway sdkPub to read enc_pub.
    if (data?.type === 'voucher-request') {
        if (!data.appHost || !data.rpId || !data.sid || !data.sdkPub) return null;
        return JSON.stringify({
            mode: 'voucher-only',
            appHost: data.appHost,
            rpId: data.rpId,
            sid: data.sid,
            sdkPub: data.sdkPub,
            clientId: data.clientId,
            appName: data.appName,
            origin: data.origin,
            brokerUrl: data.brokerUrl,
            userAgent: data.userAgent,
            clientIP: data.clientIP,
        });
    }
    if (data?.type !== 'auth-request' || !data.origin || !data.sessionId || !data.rpId) {
        return null;
    }
    return JSON.stringify({
        origin: data.origin,
        sessionId: data.sessionId,
        rpId: data.rpId,
        brokerUrl: data.brokerUrl,
        userAgent: data.userAgent,
        appName: data.appName,
        clientIP: data.clientIP,
        // Session-relay fields. Only present when the requesting SDK
        // opted into the sealed-session bootstrap. `appHost` is the
        // attestation target: omitting it makes the wallet fall back
        // to attesting `rpId` (typically the IdP at `privasys.id`,
        // which has no enclave measurements), producing a bogus
        // `Passkey (no enclave)` trust row.
        mode: data.mode,
        sdkPub: data.sdkPub,
        appHost: data.appHost,
        nonce: data.nonce,
        expectedAppSni: data.expectedAppSni,
        // OIDC client of the requesting app. Required for EncAuth voucher
        // issuance (silent rebind): without it, push-driven sign-ins mint
        // no voucher and the browser cannot silently resume sealed sessions.
        clientId: data.clientId,
        // Multi-app attestation: additional enclave hosts to voucher in the
        // same ceremony. Expo push data values are strings, so the broker
        // sends a JSON-array string; parse defensively.
        extraAppHosts: parseHostList(data.extraAppHosts),
    });
}

/** A sign-in, or a live session extended to another enclave. */
async function openConnect(data: Data, router: Router): Promise<void> {
    const payload = authRequestPayload(data);
    if (!payload) return;
    // When the SDK published a relay descriptor for this session it pins the
    // hash in the push (Expo push data is size-capped, so attribute
    // requirements and paid-disclosure vouchers ride the descriptor instead).
    // Fetch and pin-verify it (same trust model as a QR scan) and let it
    // enrich the push payload. On any failure fall back to the push payload
    // alone: a plain profile sign-in still works.
    let finalPayload = payload;
    if (data.type === 'auth-request' && typeof data.descriptorHash === 'string' && data.descriptorHash) {
        try {
            const desc = await fetchDescriptor(relayHostFrom(data.brokerUrl), String(data.sessionId), data.descriptorHash);
            if (desc?.sessionId === data.sessionId) {
                // Descriptor wins where it speaks; push-only fields
                // (userAgent, clientIP, …) survive the overlay.
                finalPayload = JSON.stringify({ ...JSON.parse(payload), ...desc });
            }
        } catch (e) {
            console.warn('[notifications] descriptor fetch failed; using push payload alone', e);
        }
    }
    router.push({ pathname: '/connect', params: { payload: finalPayload, source: 'push' } });
}

/**
 * A Drive share request or decision. Filing is a convenience and opening the
 * screen is the point: a failure to file (a sealed payload this device cannot
 * open, storage refusing a write) never stops the tap, and the screen
 * reconciles against the drive's own list on open.
 */
async function openDriveShare(data: Data, router: Router): Promise<void> {
    try {
        await fileDriveNotification(data);
    } catch (e) {
        console.warn('[notifications] could not file drive notification', e);
    }
    // An approved request opens the item in the wallet's Drive. The Drive
    // screen follows it only from the Drive it attests.
    if (data.type === 'share-decision') {
        const decision = useDriveNotificationsStore.getState().decisions.slice(-1)[0];
        if (decision?.status === 'approved' && decision.tenantId && decision.nodeId) {
            router.push({
                pathname: '/drive',
                params: {
                    section: 'shared',
                    tenant: decision.tenantId,
                    node: decision.nodeId,
                    ...(typeof data.app_id === 'string' ? { from: data.app_id } : {}),
                },
            });
            return;
        }
    }
    // Already filed above, so an open list is showing it: pushing would only
    // stack a second copy of the same view.
    if (!isRouteActive('/drive-requests')) {
        router.push({ pathname: '/drive-requests', params: { source: 'push' } });
    }
}

/**
 * An app's message the holder answers in the wallet: an approval of one act,
 * or a form. It travels sealed in the push; filing it first lets its screen
 * open without waiting for the list, and the screen looks it up by the IdP's
 * id for it.
 */
function openAppMessage(pathname: '/approval' | '/app-form', what: string, exempt: boolean): Handler {
    return async (data, router) => {
        const id = text(data.message_id);
        if (!id) {
            router.navigate('/access');
            return;
        }
        // Before the read: the lock must not ask for Face ID meanwhile.
        if (exempt) useAppLockStore.getState().expectExemptPush();
        try {
            const m = await readMessage({
                id, type: String(data.type), kind: data.kind, app_id: data.app_id,
                app_name: typeof data.app_name === 'string' ? data.app_name : undefined,
                app_host: data.app_host, sealed: data.sealed,
                app_slug: data.app_slug, app_platform_host: data.app_platform_host,
            });
            if (m) useAppMessagesStore.getState().remember(m);
        } catch (e) {
            console.warn(`[notifications] could not read the ${what}`, e);
        }
        router.push({ pathname, params: { id } });
    };
}

/**
 * An app's message to read. Its link goes only to the host the platform named
 * for the app (app_host, beside the sealed payload, never inside it), and
 * opens straight there: the app is where the holder acts on it. Without a
 * usable link, Access lists the ones still waiting.
 */
async function openAppNotice(data: Data, router: Router): Promise<void> {
    const sealed = text(data.sealed);
    const payload = sealed ? await openSealedNotification(sealed, APP_MESSAGE_TYPE) : null;
    const kind = typeof data.kind === 'string' ? data.kind : undefined;
    const appHost = typeof data.app_host === 'string' ? data.app_host : undefined;
    const messageId = text(data.message_id);
    const path = readAppMessage(payload, kind).path;
    // Drive is the wallet's own storage: its links open the wallet's Drive
    // screen, not the browser.
    const driveRoute = await driveRouteFor(appHost, path, typeof data.app_id === 'string' ? data.app_id : undefined);
    if (driveRoute) {
        if (messageId) void dismissAppMessage(messageId);
        router.push(driveRoute);
        return;
    }
    const link = appMessageLink(appHost, path);
    if (link) {
        try {
            await Linking.openURL(link);
            if (messageId) void dismissAppMessage(messageId);
            return;
        } catch (e) {
            console.warn('[notifications] could not open the app message link', e);
        }
    }
    void useAppMessagesStore.getState().refresh();
    router.navigate('/access');
}

/**
 * An attested app asking for scoped authority over something the holder
 * owns. The push carries ONLY the nonce and where to fetch: everything that
 * matters, including the key being authorised, is learned inside the attested
 * channel, or a push could show a genuine identity while binding somebody
 * else's key.
 */
function openCapabilityRequest(data: Data, router: Router): void {
    const host = String(data.app_host ?? '');
    const nonce = String(data.nonce ?? '');
    if (!host || !nonce) return;
    router.push({ pathname: '/capability-request', params: { app_host: host, nonce } });
}

/**
 * Someone this holder protects is recovering their account. The push says
 * only that: whose, and which request, are listed by the IdP for the
 * guardian's own session on the Recovery screen, which puts these first and
 * asks the guardian to unlock when their session has lapsed.
 */
function openRecoveryRequest(_data: Data, router: Router): void {
    useGuardianRequestsStore.getState().remember();
    if (!isRouteActive('/account-recovery')) router.push('/account-recovery');
}

/** One approval for a list. The card fetches the list and verifies it against this id before showing a row. */
function openVaultBatch(data: Data, router: Router): void {
    const batchId = String(data.batch_id ?? '');
    if (!batchId) return;
    useAppLockStore.getState().expectExemptPush();
    useVaultApprovalsStore.getState().rememberBatch(batchId);
    if (!isRouteActive(vaultBatchRouteName(batchId))) {
        router.push({ pathname: '/vault-approvals', params: { batch_id: batchId, source: 'push' } });
    }
}

function openVaultApproval(data: Data, router: Router): void {
    const vaultOp = String(data.vault_op ?? '');
    // Remember the capability so the Home banner and the screen list it even
    // when the holder reaches the screen another way (missed banner,
    // foreground arrival).
    useVaultApprovalsStore.getState().remember(vaultOp);
    useAppLockStore.getState().expectExemptPush();
    // Do NOT push when that screen is already up. It lists everything pending,
    // and remember() has just added this one, so a push adds no information
    // and one screen per notification: approving several promotes in a row
    // produced a stack of identical screens, each saying "nothing left to
    // approve" once its turn came, and a back press per approval to get home.
    if (!isRouteActive('/vault-approvals')) {
        router.push({ pathname: '/vault-approvals', params: { vault_op: vaultOp, source: 'push' } });
    }
}

/**
 * Attribute step-up: a relying party the holder already signed into asked for
 * MORE than the standing grant. The push carries only the capability; the
 * pending request (the delta and the authorize descriptor) is fetched over TLS
 * and run through the connect consent flow. A dead capability (completed, or
 * expired with its 5-minute authorize session, so the browser fell back to a
 * QR) does nothing: there is nothing left to act on.
 */
async function openAttributeApproval(data: Data, router: Router): Promise<void> {
    const approval = String(data.approval ?? '');
    if (!approval) return;
    try {
        const req = await fetchAttributeApproval(approval);
        if (!req) return;
        const payload = JSON.stringify({
            ...req.payload,
            mode: 'attribute-step-up',
            sessionId: req.session_id,
            clientId: req.client_id,
            approval: req.approval,
            addedAttributes: req.added,
            approvalOptions: req.options,
        });
        router.push({ pathname: '/connect', params: { payload, source: 'push' } });
    } catch (e) {
        console.warn('[notifications] attribute-approval fetch failed', e);
    }
}

/** Silent work, done whenever the notification arrives. */
const SILENT = new Map<string, Handler>([
    // Answered on another of the holder's phones: off this one too.
    [DISMISS_TYPE, async (data) => {
        if (typeof data.key === 'string') await dismissHere(data.key).catch(() => 0);
    }],
    // Another phone of the holder sent an update: fetch it.
    ['device-relay', async () => {
        await pullRelay().catch((e) => console.warn('[notifications] device relay failed', e));
    }],
]);
// An account deletion: the banner, a cancel from elsewhere, or the end. Each
// push carries only its type; what it means is read from privasys.id, and the
// wallet is never cleared on a push alone.
for (const type of DELETION_PUSH_TYPES) {
    SILENT.set(type, async () => {
        await handleDeletionPush(type).catch((e) => console.warn('[notifications] account deletion', e));
    });
}

/** What opens a screen or a link. */
const OPENS = new Map<string, Handler>([
    ['auth-request', openConnect],
    ['voucher-request', openConnect],
    ['attribute-approval', openAttributeApproval],
    ['vault-approval', openVaultApproval],
    ['vault-approval-batch', openVaultBatch],
    ['capability-request', openCapabilityRequest],
    ['recovery-request', openRecoveryRequest],
    ['share-request', openDriveShare],
    ['share-decision', openDriveShare],
    [APPROVAL_TYPE, openAppMessage('/approval', 'approval', true)],
    [APP_FORM_TYPE, openAppMessage('/app-form', 'app form', false)],
    [APP_MESSAGE_TYPE, openAppNotice],
]);

/** Handle a notification, received (tapped false) or tapped. */
export async function dispatchPush(data: Data, router: Router, tapped: boolean): Promise<void> {
    // Any notification may carry privasys.id's request that this phone show
    // its push token is its own. Answered beside whatever the notification is
    // about, never in its place.
    if (carriesBindChallenge(data)) {
        void answerBindChallenge(data).catch((e) => console.warn('[notifications] push binding failed', e));
    }
    const type = typeof data?.type === 'string' ? data.type : '';
    const silent = SILENT.get(type);
    if (silent) {
        await silent(data, router);
        return;
    }
    if (!tapped && !opensAtOnce(data)) return;
    await OPENS.get(type)?.(data, router);
}

let started = false;

/**
 * Listen for notifications, once per process however many screens use the
 * push hook: each listener set would otherwise handle one notification again,
 * and the cold-start response, which stays the same all session, would open
 * its screen on every mount.
 */
export async function startPushHandling(router: Router): Promise<void> {
    if (started) return;
    started = true;
    const Notifications = await getNotifications();

    // Cold start: a wallet launched by a tap has the response queued, and the
    // response listener may register too late to receive it, so it is read
    // here.
    try {
        const initial = await Notifications.getLastNotificationResponseAsync();
        const data = initial?.notification.request.content.data as Data | undefined;
        if (data) {
            // Deferred one tick so the router is mounted first.
            setTimeout(() => void dispatchPush(data, router, true), 0);
            void notificationAnswered(data);
        }
    } catch (e) {
        console.warn('[notifications] getLastNotificationResponseAsync failed', e);
    }
    // After the dispatch above has had its tick, so a push that marks an
    // exempt screen does so before the lock asks for Face ID.
    setTimeout(() => useAppLockStore.getState().setLaunchPushChecked(), 0);

    Notifications.addNotificationReceivedListener((n) => {
        const data = n.request.content.data as Data | undefined;
        if (data) void dispatchPush(data, router, false);
    });
    Notifications.addNotificationResponseReceivedListener((response) => {
        const data = response.notification.request.content.data as Data | undefined;
        if (!data) return;
        void dispatchPush(data, router, true);
        void notificationAnswered(data);
    });

    // Pending requests the holder never tapped: the tray now (the wallet just
    // came up) and whenever it returns to the front.
    void sweepTray();
    AppState.addEventListener('change', (state) => {
        if (state === 'active') {
            void sweepTray();
            void pullRelay().catch(() => undefined);
        }
    });
}
