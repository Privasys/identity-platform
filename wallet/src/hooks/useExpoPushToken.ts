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
            handleNotification: async () => {
                return {
                    shouldShowAlert: true,
                    shouldPlaySound: true,
                    shouldSetBadge: true,
                    shouldShowBanner: true,
                    shouldShowList: true,
                };
            },
        });
    }
    return Notifications;
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

            // Foreground notification handler - no special handling needed,
            // all notifications use the default display behavior.
            notificationListener.current = Notifications.addNotificationReceivedListener(
                () => {},
            );

            // Tap-to-open handler - fires when the user taps a notification.
            responseListener.current = Notifications.addNotificationResponseReceivedListener(
                (response) => {
                    const data = response.notification.request.content.data;
                    if (data?.type === 'auth-request' && data.origin && data.sessionId && data.rpId) {
                        const payload = JSON.stringify({
                            origin: data.origin,
                            sessionId: data.sessionId,
                            rpId: data.rpId,
                            brokerUrl: data.brokerUrl,
                            userAgent: data.userAgent,
                            appName: data.appName,
                            clientIP: data.clientIP,
                        });
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