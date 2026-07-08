import * as Device from 'expo-device';
import { useRouter, type Router } from 'expo-router';
import { useEffect, useState } from 'react';
import { AppState, Platform } from 'react-native';

import { DEFAULT_RELAY_HOST, fetchDescriptor } from '../services/descriptor';
import { getPrivasysAccount } from '../services/privasys-id';
import { registerPushTokenWithIdp } from '../services/vault-approval-api';
import { useVaultApprovalsStore } from '../stores/vaultApprovals';

let _notificationsSetup = false;

async function getNotifications() {
    const Notifications = await import('expo-notifications');
    if (!_notificationsSetup && Platform.OS !== 'web') {
        _notificationsSetup = true;
        Notifications.setNotificationHandler({
            handleNotification: async (notification) => {
                // Auth-request notifications received while the app is in
                // the foreground are surfaced directly via the connect
                // screen (see addNotificationReceivedListener below). We
                // suppress the banner / list entry / sound to avoid a
                // double prompt — the user is already looking at the app.
                const data = notification?.request?.content?.data as
                    | Record<string, unknown>
                    | undefined;
                const isAuthRequest =
                    data?.type === 'auth-request' ||
                    data?.type === 'voucher-request' ||
                    data?.type === 'vault-approval';
                return {
                    shouldShowAlert: !isAuthRequest,
                    shouldPlaySound: !isAuthRequest,
                    shouldSetBadge: !isAuthRequest,
                    shouldShowBanner: !isAuthRequest,
                    shouldShowList: !isAuthRequest,
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

/** Route an inbound notification to the right screen by its `type`. Vault
 *  approvals go to the Vault approvals screen; everything else runs through the
 *  auth/voucher connect flow. */
async function dispatchPush(data: Record<string, unknown>, router: Router): Promise<void> {
    if (data?.type === 'vault-approval') {
        const vaultOp = String(data.vault_op ?? '');
        // Remember the capability so the Home banner + the screen list it even
        // when the user reaches the screen another way (missed banner,
        // foreground arrival).
        useVaultApprovalsStore.getState().remember(vaultOp);
        router.push({
            pathname: '/vault-approvals',
            params: { vault_op: vaultOp, source: 'push' },
        });
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
        for (const n of presented) {
            const data = n.request.content.data as Record<string, unknown> | undefined;
            if (data?.type === 'vault-approval' && data.vault_op) {
                store.remember(String(data.vault_op));
            }
        }
    } catch (e) {
        console.warn('[notifications] sweep presented approvals failed', e);
    }
}

/** Register the Expo push token with the IdP when a privasys.id session exists,
 *  so the IdP can push vault approvals keyed by the owner sub. Best-effort. */
async function maybeRegisterPushToken(token: string): Promise<void> {
    const account = getPrivasysAccount();
    if (!account?.sessionToken) return;
    try {
        await registerPushTokenWithIdp(account.sessionToken, token);
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

function publishToken(t: string | null): void {
    ambientPushToken = t;
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
                    setTimeout(() => void dispatchPush(data, router), 0);
                }
            }
        } catch (e) {
            console.warn('[notifications] getLastNotificationResponseAsync failed', e);
        }
    }

    // Foreground notification handler — when an auth-request arrives while
    // the app is open we route straight to the connect screen, instead of
    // forcing the user to dismiss a banner first. The notification handler
    // above is what suppresses the banner for this case. Registered once
    // globally so a single inbound notification produces a single push.
    Notifications.addNotificationReceivedListener((n) => {
        const data = n.request.content.data as Record<string, unknown> | undefined;
        if (!data) return;
        void dispatchPush(data, router);
    });

    // Tap-to-open handler — fires when the user taps a notification
    // delivered while the app was in the background. Registered once
    // globally; we deliberately never call .remove() because the listeners
    // need to live for the entire app lifetime.
    Notifications.addNotificationResponseReceivedListener((response) => {
        const data = response.notification.request.content.data as
            | Record<string, unknown>
            | undefined;
        if (!data) return;
        void dispatchPush(data, router);
    });

    // Surface pending approvals the user never tapped: sweep the tray now (app
    // just came up) and again whenever it returns to the foreground.
    void sweepPresentedApprovals();
    AppState.addEventListener('change', (state) => {
        if (state === 'active') void sweepPresentedApprovals();
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
