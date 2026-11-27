import * as Device from 'expo-device';
import { useRouter, type Router } from 'expo-router';
import { useEffect, useState } from 'react';
import { AppState, Linking, Platform } from 'react-native';

import { APP_FORM_TYPE } from '../services/app-form';
import { APPROVAL_TYPE } from '../services/approval';
import { APP_MESSAGE_TYPE, appMessageLink, readAppMessage } from '../services/app-message';
import { DEFAULT_RELAY_HOST, fetchDescriptor } from '../services/descriptor';
import { DRIVE_ID, driveRouteFor } from '../services/drive-files';
import { pullRelay } from '../services/device-sync';
import { mainAccountUserId } from '../services/devices';
import { ensureNotifySealKey, openSealedNotification } from '../services/notify-seal';
import { getPrivasysAccount } from '../services/privasys-id';
import { fetchAttributeApproval } from '../services/attribute-approval-api';
import { registerPushTokenWithIdp } from '../services/vault-approval-api';
import { dismissAppMessage, readMessage, useAppMessagesStore } from '../stores/app-messages';
import { useDriveNotificationsStore } from '../stores/drive-notifications';
import { useGuardianRequestsStore } from '../stores/guardian-requests';
import { useAppLockStore } from '../stores/app-lock';
import { useVaultApprovalsStore } from '../stores/vaultApprovals';
import { vaultBatchRouteName } from '../services/vault-approval-batch';
import { isRouteActive } from '../utils/active-route';
import { DELETION_PUSH_TYPES, handleDeletionPush } from '../services/account-deletion-events';
import {
    dismissClosed,
    dismissElsewhere,
    dismissHere,
    dismissStale,
    DISMISS_TYPE,
    setOwnPushToken,
} from '../services/notification-dismiss';
import { answerBindChallenge, answerFromTray, carriesBindChallenge } from '../services/push-bind';

let _notificationsSetup = false;

/**
 * Requests the holder is waiting on right now, because they started something
 * elsewhere: a sign-in, an app reaching another enclave, an approval. Received
 * while the wallet is open, these open at once and show no banner. Anything
 * else (an app's message or form, a Drive share, a deletion notice) shows its
 * banner and opens only on a tap, as it does when the wallet is closed, so it
 * never takes the holder away from what they are doing.
 */
const OPENS_AT_ONCE = new Set<string>([
    'auth-request',
    'voucher-request',
    'vault-approval',
    'vault-approval-batch',
    'attribute-approval',
    'capability-request',
    'recovery-request',
    APPROVAL_TYPE,
]);

function opensAtOnce(data: Record<string, unknown> | undefined): boolean {
    return typeof data?.type === 'string' && OPENS_AT_ONCE.has(data.type);
}

async function getNotifications() {
    const Notifications = await import('expo-notifications');
    if (!_notificationsSetup && Platform.OS !== 'web') {
        _notificationsSetup = true;
        Notifications.setNotificationHandler({
            handleNotification: async (notification) => {
                // A request that opens at once needs no banner too: the
                // holder is already looking at its screen.
                const data = notification?.request?.content?.data as
                    | Record<string, unknown>
                    | undefined;
                const quiet = opensAtOnce(data);
                return {
                    shouldShowAlert: !quiet,
                    shouldPlaySound: !quiet,
                    shouldSetBadge: !quiet,
                    shouldShowBanner: !quiet,
                    shouldShowList: !quiet,
                };
            },
        });
    }
    return Notifications;
}

/** Build the connect-screen JSON payload from an auth-request or a
 *  voucher-request notification's data, or null when it's neither / malformed. */
function authRequestPayload(data: Record<string, unknown>): string | null {
    // Voucher-only: extend a LIVE session to an additional enclave with one
    // biometric — no sign-in ceremony. Needs the target host + the IdP session
    // row (sid) the browser is polling + a throwaway sdkPub to read enc_pub.
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
        // attestation target — omitting it makes the wallet fall back
        // to attesting `rpId` (typically the IdP at `privasys.id`,
        // which has no enclave measurements), producing a bogus
        // `Passkey (no enclave)` trust row.
        mode: data.mode,
        sdkPub: data.sdkPub,
        appHost: data.appHost,
        nonce: data.nonce,
        expectedAppSni: data.expectedAppSni,
        // OIDC client of the requesting app. Required for EncAuth voucher
        // issuance (silent rebind) — without it, push-driven sign-ins mint
        // no voucher and the browser cannot silently resume sealed sessions.
        clientId: data.clientId,
        // Multi-app attestation: additional enclave hosts to voucher in the
        // same ceremony. Expo push data values are strings, so the broker
        // sends a JSON-array string; parse defensively.
        extraAppHosts: parseHostList(data.extraAppHosts),
    });
}

/** Relay host for a broker URL (`wss://relay.privasys.org/relay` → host). */
function relayHostFrom(brokerUrl: unknown): string {
    try {
        const host = new URL(String(brokerUrl ?? '')).host;
        return host || DEFAULT_RELAY_HOST;
    } catch {
        return DEFAULT_RELAY_HOST;
    }
}

/** File a drive share notification into the store: unseal the payload,
 *  update the attribute referential and the request/decision inboxes.
 *  Returns true when `data` was a drive notification (handled). */
async function fileDriveNotification(data: Record<string, unknown>): Promise<boolean> {
    const type = data?.type;
    if (type !== 'share-request' && type !== 'share-decision') return false;
    const sealed = typeof data.sealed === 'string' ? data.sealed : '';
    if (!sealed) return true; // unsealed generic push: nothing to file
    const payload = await openSealedNotification(sealed, String(type));
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

/** Route an inbound notification to the right screen by its `type`. Vault
 *  approvals go to the Vault approvals screen; drive share notifications file
 *  into the drive-notifications store and open the requests screen; everything
 *  else runs through the auth/voucher connect flow. */
async function dispatchPush(data: Record<string, unknown>, router: Router, tapped: boolean): Promise<void> {
    // Any notification may carry privasys.id's request that this phone show its
    // push token is its own. Answered beside whatever the notification is
    // about, never in its place.
    if (carriesBindChallenge(data)) answerChallengeCarriedBy(data);
    if (typeof data?.type === 'string' && DELETION_PUSH_TYPES.has(data.type)) {
        // An account deletion: the banner, a cancel from elsewhere, or the end.
        // Each push carries only its type; what it means is read from
        // privasys.id, and the wallet is never cleared on a push alone.
        await handleDeletionPush(data.type).catch((e) => console.warn('[notifications] account deletion', e));
        return;
    }
    if (data?.type === DISMISS_TYPE) {
        // Answered on another of the holder's phones: off this one too. Silent.
        if (typeof data.key === 'string') await dismissHere(data.key).catch(() => 0);
        return;
    }
    if (data?.type === 'device-relay') {
        // Another phone of the holder sent an update: fetch it. Silent.
        await pullRelay().catch((e) => console.warn('[notifications] device relay failed', e));
        return;
    }
    // Everything below opens a screen or a link: on arrival, only for what
    // the holder is waiting on; anything else waits for the tap.
    if (!tapped && !opensAtOnce(data)) return;
    if (data?.type === 'share-request' || data?.type === 'share-decision') {
        // Filing is a convenience and opening the screen is the point. A
        // failure here (a sealed payload this device cannot open, storage
        // refusing a write) used to abort the whole tap, so the holder pressed
        // a notification and nothing happened. The screen reconciles against
        // the drive's own list on open, so it shows the request either way.
        try {
            await fileDriveNotification(data);
        } catch (e) {
            console.warn('[notifications] could not file drive notification', e);
        }
        // An approved request opens the item in the wallet's Drive. The Drive
        // screen follows it only from the Drive it attests.
        if (data?.type === 'share-decision') {
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
        // Already filed above, so an open list is showing it: pushing would
        // only stack a second copy of the same view. See the vault-approval
        // branch below for what that cost.
        if (!isRouteActive('/drive-requests')) {
            router.push({ pathname: '/drive-requests', params: { source: 'push' } });
        }
        return;
    }
    if (data?.type === APPROVAL_TYPE) {
        // An app waiting, now, on the holder's yes or no to one act. Filed
        // first, as a form is, so its screen opens without the list.
        const id = typeof data.message_id === 'string' ? data.message_id : '';
        if (!id) {
            router.navigate('/access');
            return;
        }
        // Before the read: the lock must not ask for Face ID meanwhile.
        useAppLockStore.getState().expectExemptPush();
        try {
            const m = await readMessage({
                id, type: APPROVAL_TYPE, kind: data.kind, app_id: data.app_id,
                app_name: typeof data.app_name === 'string' ? data.app_name : undefined,
                app_host: data.app_host, sealed: data.sealed,
                app_slug: data.app_slug, app_platform_host: data.app_platform_host,
            });
            if (m) useAppMessagesStore.getState().remember(m);
        } catch (e) {
            console.warn('[notifications] could not read the approval', e);
        }
        router.push({ pathname: '/approval', params: { id } });
        return;
    }
    if (data?.type === APP_FORM_TYPE) {
        // A question to answer in the wallet. The form travels sealed in the
        // push; filing it first lets its screen open without waiting for the
        // list, and the screen looks the form up by the IdP's id for it.
        const id = typeof data.message_id === 'string' ? data.message_id : '';
        if (!id) {
            router.navigate('/access');
            return;
        }
        try {
            const m = await readMessage({
                id, type: APP_FORM_TYPE, kind: data.kind, app_id: data.app_id,
                app_name: typeof data.app_name === 'string' ? data.app_name : undefined,
                app_host: data.app_host, sealed: data.sealed,
                app_slug: data.app_slug, app_platform_host: data.app_platform_host,
            });
            if (m) useAppMessagesStore.getState().remember(m);
        } catch (e) {
            console.warn('[notifications] could not read the app form', e);
        }
        router.push({ pathname: '/app-form', params: { id } });
        return;
    }
    if (data?.type === APP_MESSAGE_TYPE) {
        // An app's message. Its link goes only to the host the platform named
        // for the app (app_host, beside the sealed payload, never inside it),
        // and opens straight there: the app is where the holder acts on it.
        // Without a usable link, Access lists the ones still waiting.
        const sealed = typeof data.sealed === 'string' ? data.sealed : '';
        const payload = sealed ? await openSealedNotification(sealed, APP_MESSAGE_TYPE) : null;
        const kind = typeof data.kind === 'string' ? data.kind : undefined;
        const appHost = typeof data.app_host === 'string' ? data.app_host : undefined;
        const path = readAppMessage(payload, kind).path;
        // Drive is the wallet's own storage: its links open the wallet's Drive
        // screen, not the browser.
        const driveRoute = await driveRouteFor(appHost, path, typeof data.app_id === 'string' ? data.app_id : undefined);
        if (driveRoute) {
            if (typeof data.message_id === 'string' && data.message_id) void dismissAppMessage(data.message_id);
            router.push(driveRoute);
            return;
        }
        const link = appMessageLink(appHost, path);
        if (link) {
            try {
                await Linking.openURL(link);
                if (typeof data.message_id === 'string' && data.message_id) {
                    void dismissAppMessage(data.message_id);
                }
                return;
            } catch (e) {
                console.warn('[notifications] could not open the app message link', e);
            }
        }
        void useAppMessagesStore.getState().refresh();
        router.navigate('/access');
        return;
    }
    if (data?.type === 'capability-request') {
        // An attested app asking for scoped authority over something the holder
        // owns. The push carries ONLY the nonce and where to fetch: everything
        // that matters, including the key being authorised, is learned inside
        // the attested channel, or a push could show a genuine identity while
        // binding somebody else's key.
        const host = String(data.app_host ?? '');
        const nonce = String(data.nonce ?? '');
        if (!host || !nonce) return;
        router.push({ pathname: '/capability-request', params: { app_host: host, nonce } });
        return;
    }
    if (data?.type === 'recovery-request') {
        // Someone this holder protects is recovering their account. The push
        // says only that: whose, and which request, are listed by the IdP for
        // the guardian's own session on the Recovery screen, which puts these
        // first and asks the guardian to unlock when their session has lapsed.
        useGuardianRequestsStore.getState().remember();
        if (!isRouteActive('/account-recovery')) {
            router.push('/account-recovery');
        }
        return;
    }
    if (data?.type === 'vault-approval-batch') {
        // One approval for a list. The card fetches the list and verifies it
        // against this id before showing a row.
        const batchId = String(data.batch_id ?? '');
        if (!batchId) return;
        useAppLockStore.getState().expectExemptPush();
        useVaultApprovalsStore.getState().rememberBatch(batchId);
        if (!isRouteActive(vaultBatchRouteName(batchId))) {
            router.push({ pathname: '/vault-approvals', params: { batch_id: batchId, source: 'push' } });
        }
        return;
    }
    if (data?.type === 'vault-approval') {
        const vaultOp = String(data.vault_op ?? '');
        // Remember the capability so the Home banner + the screen list it even
        // when the user reaches the screen another way (missed banner,
        // foreground arrival).
        useVaultApprovalsStore.getState().remember(vaultOp);
        useAppLockStore.getState().expectExemptPush();
        // Do NOT push when that screen is already up. It lists everything
        // pending, and remember() has just added this one, so a push adds no
        // information and one screen per notification.
        //
        // Approving several promotes in a row produced exactly that: a stack of
        // identical screens, each saying "nothing left to approve" once its turn
        // came, and a back press needed per approval to get home (2026-09-10).
        if (!isRouteActive('/vault-approvals')) {
            router.push({
                pathname: '/vault-approvals',
                params: { vault_op: vaultOp, source: 'push' },
            });
        }
        return;
    }
    if (data?.type === 'attribute-approval') {
        // Attribute step-up: a relying party the holder already signed into
        // asked for MORE than the standing grant. The push carries only the
        // capability; fetch the pending request (delta + the authorize
        // descriptor) over TLS and run it through the connect consent flow.
        // A dead capability (completed, or expired with its 5-minute
        // authorize session — the browser fell back to a QR) is a no-op: no
        // store, no banner; there is nothing left to act on.
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
        return;
    }
    const payload = authRequestPayload(data);
    if (!payload) return;

    // When the SDK published a relay descriptor for this session it pins the
    // hash in the push (Expo push data is size-capped, so attribute
    // requirements and paid-disclosure vouchers ride the descriptor instead).
    // Fetch and pin-verify it — same trust model as a QR scan — and let it
    // enrich the push payload. On any failure fall back to the push payload
    // alone (pre-descriptor behaviour: plain profile sign-in still works).
    let finalPayload = payload;
    if (
        data.type === 'auth-request' &&
        typeof data.descriptorHash === 'string' &&
        data.descriptorHash
    ) {
        try {
            const desc = await fetchDescriptor(
                relayHostFrom(data.brokerUrl),
                String(data.sessionId),
                data.descriptorHash,
            );
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

/** Sweep the OS notification tray for vault-approval notifications and remember
 *  their capabilities. This is what makes pending approvals visible when the
 *  user just OPENS the wallet (app icon) after a push arrived while it was
 *  backgrounded — without a tap there is no response event and no cold-start
 *  record, so the capability would otherwise never reach the app. The
 *  notification carries the vault_op in its data (see the IdP push payload);
 *  server-side expiry + the store's refresh prune anything already dead. */
async function sweepPresentedApprovals(): Promise<void> {
    if (Platform.OS === 'web') return;
    try {
        const Notifications = await getNotifications();
        const presented = await Notifications.getPresentedNotificationsAsync();
        const store = useVaultApprovalsStore.getState();
        let approvals = false;
        for (const n of presented) {
            const data = n.request.content.data as Record<string, unknown> | undefined;
            if (data?.type === 'vault-approval' && data.vault_op) {
                store.remember(String(data.vault_op));
                approvals = true;
            }
            if (data?.type === 'vault-approval-batch' && data.batch_id) {
                store.rememberBatch(String(data.batch_id));
                approvals = true;
            }
            // A guardian's recovery request: Access shows it as waiting even
            // when the wallet was opened from its icon rather than the push.
            if (data?.type === 'recovery-request') {
                useGuardianRequestsStore.getState().remember();
            }
            // Drive share notifications carry their sealed payload in the
            // notification itself: filing from the tray means the request
            // (and its attributes) are visible as soon as the wallet opens,
            // tap or no tap.
            if (data?.type === 'share-request' || data?.type === 'share-decision') {
                void fileDriveNotification(data);
            }
        }
        // An approval answered on another of the holder's phones, or expired,
        // leaves its notification here: the silent push that would clear it is
        // rationed by Apple and never reaches a wallet that was swiped away.
        // So ask privasys.id which are still open, and take the others off.
        if (approvals) {
            await store.refresh();
            await store.refreshBatches();
            const live = useVaultApprovalsStore.getState();
            await dismissClosed({
                // Known less the ones privasys.id reports gone: a request it could
                // not be asked about just now stays, so a lost connection never
                // takes a live notification away.
                'vault-approval': new Set(live.knownOps),
                'vault-approval-batch': new Set(live.batchIds),
            });
        }
    } catch (e) {
        console.warn('[notifications] sweep presented approvals failed', e);
    }
}

/** Register the Expo push token with the IdP when a privasys.id session exists,
 *  so the IdP can push vault approvals keyed by the owner sub. Also registers
 *  the device's notification-sealing public key so app notifications (drive
 *  share requests) can carry sealed payloads. Best-effort. */
/** A notification tapped here: tell the holder's other phones to clear their
 *  copy. On a cold start the token may not be published yet; a notification
 *  arrived, so permission is there to read it. */
async function answeredHere(data: Record<string, unknown>): Promise<void> {
    if (Platform.OS === 'web') return;
    let token = ambientPushToken;
    if (!token) {
        try {
            const Notifications = await getNotifications();
            token = (await Notifications.getExpoPushTokenAsync()).data;
        } catch {
            return;
        }
    }
    await dismissElsewhere(data, token);
}

/** Clear notifications that can no longer be answered, then file the rest. */
async function sweepTray(): Promise<void> {
    // Before anything is cleared: a notification still in the tray may carry
    // the challenge.
    await answerFromTray(ambientPushToken).catch((e) => console.warn('[notifications] push binding from the tray failed', e));
    await dismissStale().catch((e) => console.warn('[notifications] stale sweep failed', e));
    await sweepPresentedApprovals();
}

async function maybeRegisterPushToken(token: string): Promise<void> {
    const account = getPrivasysAccount();
    if (!account?.sessionToken) return;
    // Only register with a session that is still valid. A cold start often holds
    // a stored-but-expired privasys.id session; posting it to the IdP just 401s
    // (register push token failed (401)). The token re-registers on the next
    // sign-in (connect flow) with a fresh session, so skipping here is safe.
    if (!account.sessionExpiresAt || Date.now() >= account.sessionExpiresAt) return;
    try {
        let encPub = '';
        try {
            encPub = await ensureNotifySealKey();
        } catch (e) {
            console.warn('[notifications] sealing key unavailable; registering token alone', e);
        }
        await registerPushTokenWithIdp(account.sessionToken, token, encPub, mainAccountUserId(account.userId));
    } catch (e) {
        console.warn('[notifications] register push token with IdP failed', e);
    }
}

/** Parse the broker's JSON-array-string host list ("[\"a\",\"b\"]") safely. */
function parseHostList(v: unknown): string[] | undefined {
    if (Array.isArray(v)) return v.filter((h): h is string => typeof h === 'string');
    if (typeof v !== 'string' || !v) return undefined;
    try {
        const arr = JSON.parse(v);
        return Array.isArray(arr)
            ? arr.filter((h): h is string => typeof h === 'string')
            : undefined;
    } catch {
        return undefined;
    }
}

let ambientPushToken: string | null = null;

/** Tell privasys.id again what this device wants (the number on its icon),
 *  when the wallet holds a live session. Otherwise the next sign-in does. */
export async function registerPushTokenAgain(): Promise<void> {
    if (ambientPushToken) await maybeRegisterPushToken(ambientPushToken);
}

/** Get the current push token without a hook (for non-component code). */
export function getAmbientPushToken(): string | null {
    return ambientPushToken;
}

// ---------------------------------------------------------------------------
// Module-level singletons.
//
// Push-notification listener registration MUST happen exactly once per app
// process, regardless of how many components call useExpoPushToken(). The
// previous design registered listeners (and re-read getLastNotificationRespo-
// nseAsync) inside the hook's useEffect, which meant:
//
//   - Each call site (_layout, settings, connect.tsx, …) attached its own
//     pair of listeners. A single inbound notification then fired N callbacks
//     and produced N router.push('/connect'…) calls.
//   - getLastNotificationResponseAsync() returns the same record across the
//     whole session. Every fresh mount of /connect re-read it and pushed
//     /connect AGAIN, producing the infinite loop the user observed when the
//     SDK sent a push.
//
// We split the responsibilities:
//   - registerPushHandlers(router) is a global side-effect, invoked once.
//   - useExpoPushToken() is a thin hook that exposes the ambient token, plus
//     a per-instance subscription to token changes.
// ---------------------------------------------------------------------------

const tokenSubscribers = new Set<(t: string | null) => void>();
let tokenRegistrationStarted = false;
let listenersRegistered = false;
let coldStartHandled = false;

/** A challenge that arrived before this phone knew its push token. A wallet
 *  opened by a tap on a notification handles that notification first and
 *  learns its token after, so the answer waits for the token. The latest one
 *  only: an older nonce has been replaced or has run out. */
let challengeHeld: Record<string, unknown> | null = null;

function answerChallengeCarriedBy(data: Record<string, unknown>): void {
    if (!ambientPushToken) {
        challengeHeld = data;
        return;
    }
    void answerBindChallenge(data, ambientPushToken).catch((e) => console.warn('[notifications] push binding failed', e));
}

function publishToken(t: string | null): void {
    ambientPushToken = t;
    if (t && challengeHeld) {
        const held = challengeHeld;
        challengeHeld = null;
        answerChallengeCarriedBy(held);
    }
    setOwnPushToken(t);
    for (const fn of tokenSubscribers) fn(t);
}

async function registerForPushNotifications(): Promise<void> {
    if (tokenRegistrationStarted) return;
    tokenRegistrationStarted = true;

    if (!Device.isDevice) return;
    const Notifications = await getNotifications();

    const { status: existingStatus } = await Notifications.getPermissionsAsync();
    let finalStatus = existingStatus;

    if (existingStatus !== 'granted') {
        const { status } = await Notifications.requestPermissionsAsync();
        finalStatus = status;
    }

    if (finalStatus !== 'granted') return;

    const token = (await Notifications.getExpoPushTokenAsync()).data;
    publishToken(token);
    // Tell the IdP our token so it can push vault approvals to this owner.
    void maybeRegisterPushToken(token);

    if (Platform.OS === 'android') {
        Notifications.setNotificationChannelAsync('default', {
            name: 'default',
            importance: Notifications.AndroidImportance.MAX,
        });
    }
}

async function setupListeners(router: Router): Promise<void> {
    if (listenersRegistered) return;
    listenersRegistered = true;

    const Notifications = await getNotifications();

    // Cold-start: if the app was launched by tapping a notification, the
    // response is queued and addNotificationResponseReceivedListener may
    // register too late to receive it. Read it explicitly — but ONLY ONCE
    // per process, otherwise every subsequent navigation that mounts a
    // hook would re-push /connect from the same stale response, producing
    // an infinite loop.
    if (!coldStartHandled) {
        coldStartHandled = true;
        try {
            const initial = await Notifications.getLastNotificationResponseAsync();
            if (initial) {
                const data = initial.notification.request.content.data as
                    | Record<string, unknown>
                    | undefined;
                if (data) {
                    // Defer one tick so the router is mounted before pushing.
                    setTimeout(() => void dispatchPush(data, router, true), 0);
                    void answeredHere(data);
                }
            }
        } catch (e) {
            console.warn('[notifications] getLastNotificationResponseAsync failed', e);
        }
        // After the dispatch above has had its tick, so a push that marks an
        // exempt screen does so before the lock asks for Face ID.
        setTimeout(() => useAppLockStore.getState().setLaunchPushChecked(), 0);
    }

    // A notification received while the wallet is open: a request the holder
    // is waiting on opens at once (OPENS_AT_ONCE); anything else only does its
    // silent work, and its banner opens it on a tap. Registered once globally,
    // so one notification is handled once.
    Notifications.addNotificationReceivedListener((n) => {
        const data = n.request.content.data as Record<string, unknown> | undefined;
        if (!data) return;
        void dispatchPush(data, router, false);
    });

    // A tapped notification, whatever its type. Registered once globally and
    // never removed: it lives as long as the app.
    Notifications.addNotificationResponseReceivedListener((response) => {
        const data = response.notification.request.content.data as
            | Record<string, unknown>
            | undefined;
        if (!data) return;
        void dispatchPush(data, router, true);
        void answeredHere(data);
    });

    // Surface pending approvals the user never tapped: sweep the tray now (app
    // just came up) and again whenever it returns to the foreground.
    void sweepTray();
    AppState.addEventListener('change', (state) => {
        if (state === 'active') {
            void sweepTray();
            void pullRelay().catch(() => undefined);
        }
    });
}

export function useExpoPushToken(): string | null {
    const [expoPushToken, setExpoPushToken] = useState<string | null>(ambientPushToken);
    const router = useRouter();

    useEffect(() => {
        if (Platform.OS === 'web') return;
        registerForPushNotifications();
        setupListeners(router);
    }, [router]);

    useEffect(() => {
        tokenSubscribers.add(setExpoPushToken);
        return () => {
            tokenSubscribers.delete(setExpoPushToken);
        };
    }, []);

    return expoPushToken;
}
