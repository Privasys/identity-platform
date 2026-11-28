import { useRouter } from 'expo-router';
import { useEffect, useState } from 'react';
import { Platform } from 'react-native';

import { registerForPushNotifications } from '../services/push-registration';
import { startPushHandling } from '../services/push-router';
import { getPushToken, subscribePushToken } from '../services/push-token';

/**
 * This phone's push token, once known. The first use starts the wallet's push
 * handling (permission, registration, listeners); both run once per process,
 * however many screens use the hook.
 */
export function useExpoPushToken(): string | null {
    const [expoPushToken, setExpoPushToken] = useState<string | null>(getPushToken());
    const router = useRouter();

    useEffect(() => {
        if (Platform.OS === 'web') return;
        void registerForPushNotifications();
        void startPushHandling(router);
    }, [router]);

    useEffect(() => subscribePushToken(setExpoPushToken), []);

    return expoPushToken;
}
