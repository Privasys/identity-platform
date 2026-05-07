import * as Device from 'expo-device';
import { useRouter, type Router } from 'expo-router';
import { useEffect, useState } from 'react';
import { Platform } from 'react-native';

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
                const isAuthRequest = data?.type === 'auth-request';
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

/** Build the connect-screen JSON payload from an auth-request notification's data. */
function authRequestPayload(data: Record<string, unknown>): string | null {
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
        // session-relay (Phase E): only present when the requesting SDK
        // opted into the sealed-session bootstrap.
        mode: data.mode,
        sdkPub: data.sdkPub,
        nonce: data.nonce,
        expectedAppSni: data.expectedAppSni,
    });
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
                const payload = data ? authRequestPayload(data) : null;
                if (payload) {
                    // Defer one tick so the router is mounted before pushing.
                    setTimeout(() => {
                        router.push({ pathname: '/connect', params: { payload, source: 'push' } });
                    }, 0);
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
        const payload = authRequestPayload(data);
        if (payload) {
            router.push({ pathname: '/connect', params: { payload, source: 'push' } });
        }
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
        const payload = authRequestPayload(data);
        if (payload) {
            router.push({ pathname: '/connect', params: { payload, source: 'push' } });
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
