import Constants from 'expo-constants';
import * as Device from 'expo-device';
import { useState, useEffect } from 'react';
import { Platform } from 'react-native';

import { Text, View, Button } from './Themed';

async function getNotifications() {
    return import('expo-notifications');
}

export default function NotificationsProvider() {
    const [expoPushToken, setExpoPushToken] = useState('');
    const [channels, setChannels] = useState<{ id: string }[]>([]);
    const [notification, setNotification] = useState<{
        request: { content: { title?: string | null; body?: string | null; data?: Record<string, unknown> } };
    } | undefined>(undefined);

    useEffect(() => {
        if (Platform.OS === 'web') return;

        async function setup() {
            const Notifications = await getNotifications();

            Notifications.setNotificationHandler({
                handleNotification: async () => ({
                    shouldPlaySound: false,
                    shouldSetBadge: false,
                    shouldShowBanner: true,
                    shouldShowList: true
                })
            });

            registerForPushNotificationsAsync().then((token) => token && setExpoPushToken(token));

            if (Platform.OS === 'android') {
                Notifications.getNotificationChannelsAsync().then((value) =>
                    setChannels(value ?? [])
                );
            }

            const notificationListener = Notifications.addNotificationReceivedListener(
                (n) => setNotification(n)
            );
            const responseListener = Notifications.addNotificationResponseReceivedListener(
                (response) => console.log(response)
            );

            return () => {
                notificationListener.remove();
                responseListener.remove();
            };
        }

        let cleanup: (() => void) | undefined;
        setup().then((c) => { cleanup = c; });
        return () => cleanup?.();
    }, []);

    return (
        <View style={{ flex: 1, alignItems: 'center', justifyContent: 'space-around' }}>
            <Text>
                Your expo push token:
                {expoPushToken}
            </Text>
            <Text>
                {`Channels: ${JSON.stringify(
                    channels.map((c) => c.id),
                    null,
                    2
                )}`}
            </Text>
            <View style={{ alignItems: 'center', justifyContent: 'center' }}>
                <Text>
                    Title:
                    {notification && notification.request.content.title}
                </Text>
                <Text>
                    Body:
                    {notification && notification.request.content.body}
                </Text>
                <Text>
                    Data:
                    {notification && JSON.stringify(notification.request.content.data)}
                </Text>
            </View>
            <Button
                title="Press to schedule a notification"
                onPress={async () => {
                    await schedulePushNotification();
                }}
            />
        </View>
    );
}

async function schedulePushNotification() {
    const Notifications = await getNotifications();
    await Notifications.scheduleNotificationAsync({
        content: {
            title: "You've got mail! 📬",
            body: 'Here is the notification body',
            data: { data: 'goes here', test: { test1: 'more data' } }
        },
        trigger: { type: Notifications.SchedulableTriggerInputTypes.TIME_INTERVAL, seconds: 2 }
    });
}

async function registerForPushNotificationsAsync() {
    const Notifications = await getNotifications();
    let token;

    if (Platform.OS === 'android') {
        await Notifications.setNotificationChannelAsync('myNotificationChannel', {
            name: 'A channel is needed for the permissions prompt to appear',
            importance: Notifications.AndroidImportance.MAX,
            vibrationPattern: [0, 250, 250, 250],
            lightColor: '#FF231F7C'
        });
    }

    if (Device.isDevice) {
        const { status: existingStatus } = await Notifications.getPermissionsAsync();
        let finalStatus = existingStatus;
        if (existingStatus !== 'granted') {
            const { status } = await Notifications.requestPermissionsAsync();
            finalStatus = status;
        }
        if (finalStatus !== 'granted') {
            alert('Failed to get push token for push notification!');
            return;
        }
        try {
            const projectId =
                Constants?.expoConfig?.extra?.eas?.projectId ?? Constants?.easConfig?.projectId;
            if (!projectId) {
                throw new Error('Project ID not found');
            }
            token = (await Notifications.getExpoPushTokenAsync({ projectId })).data;
            console.log(token);
        } catch (e) {
            token = `${e}`;
        }
    } else {
        alert('Must use physical device for Push Notifications');
    }

    return token;
}
