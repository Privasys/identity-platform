import * as Device from 'expo-device';
import { useRouter } from 'expo-router';
import { useEffect, useState, useRef } from 'react';
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

export function useExpoPushToken() {
    const [expoPushToken, setExpoPushToken] = useState<string | null>(ambientPushToken);
    const router = useRouter();
    const responseListener = useRef<{ remove(): void } | null>(null);
    const notificationListener = useRef<{ remove(): void } | null>(null);

    useEffect(() => {
        if (Platform.OS === 'web') return;

        async function registerForPushNotifications() {
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
            ambientPushToken = token;
            setExpoPushToken(token);

            if (Platform.OS === 'android') {
                Notifications.setNotificationChannelAsync('default', {
                    name: 'default',
                    importance: Notifications.AndroidImportance.MAX
                });
            }
        }

        async function setupListeners() {
            const Notifications = await getNotifications();

            // Cold-start: if the app was launched by tapping a notification,
            // the response is queued and addNotificationResponseReceivedListener
            // may register too late to receive it. Read it explicitly.
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

            // Foreground notification handler — when an auth-request
            // arrives while the app is open we route straight to the
            // connect screen, instead of forcing the user to dismiss a
            // banner first. The notification handler above is what
            // suppresses the banner for this case.
            notificationListener.current = Notifications.addNotificationReceivedListener(
                (n) => {
                    const data = n.request.content.data as Record<string, unknown> | undefined;
                    if (!data) return;
                    const payload = authRequestPayload(data);
                    if (payload) {
                        router.push({ pathname: '/connect', params: { payload, source: 'push' } });
                    }
                },
            );

            // Tap-to-open handler — fires when the user taps a notification
            // delivered while the app was in the background.
            responseListener.current = Notifications.addNotificationResponseReceivedListener(
                (response) => {
                    const data = response.notification.request.content.data as
                        | Record<string, unknown>
                        | undefined;
                    if (!data) return;
                    const payload = authRequestPayload(data);
                    if (payload) {
                        router.push({ pathname: '/connect', params: { payload, source: 'push' } });
                    }
                }
            );
        }

        registerForPushNotifications();
        setupListeners();

        return () => {
            notificationListener.current?.remove();
            responseListener.current?.remove();
        };
    }, [router]);

    return expoPushToken;
}