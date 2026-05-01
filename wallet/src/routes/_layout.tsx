import * as Integrity from '@expo/app-integrity';
import FontAwesome from '@expo/vector-icons/FontAwesome';
import { DarkTheme, DefaultTheme, ThemeProvider } from '@react-navigation/native';
import { useFonts } from 'expo-font';
import { useKeepAwake } from 'expo-keep-awake';
import { Stack, useRouter } from 'expo-router';
import * as SplashScreen from 'expo-splash-screen';
import { useEffect, useState, useCallback } from 'react';
import { Platform } from 'react-native';
import 'react-native-get-random-values';
import 'react-native-reanimated';

import { SplashAnimation } from '@/components/SplashAnimation';
import { useColorScheme } from '@/components/useColorScheme';
import { useDeviceUuid } from '@/hooks/useDeviceUuid';
import { useExpoPushToken } from '@/hooks/useExpoPushToken';
import { useAuthStore } from '@/stores/auth';
import { useConsentStore } from '@/stores/consent';
import { useProfileStore } from '@/stores/profile';
import { useSessionsStore } from '@/stores/sessions';
import { useSettingsStore } from '@/stores/settings';
import { useTrustedAppsStore } from '@/stores/trusted-apps';
import { checkDeviceSecurity } from '@/services/security';
import { installLogCapture } from '@/utils/logs';

// Capture console output into an in-memory ring buffer as early as
// possible so the Settings → Logs screen and the Connect → Report Error
// flow can surface the lines that led up to a problem.
installLogCapture();
// import * as Sentry from '@sentry/react-native';

// Sentry.init({
//     dsn: process.env.EXPO_PUBLIC_SENTRY_DSN,
//     environment: process.env.STAGE || process.env.NODE_ENV || 'development',
//     debug: true,

//     // Adds more context data to events (IP address, cookies, user, etc.)
//     // For more information, visit: https://docs.sentry.io/platforms/react-native/data-management/data-collected/
//     sendDefaultPii: true,

//     // Configure Session Replay
//     replaysSessionSampleRate: 0.1,
//     replaysOnErrorSampleRate: 1,
//     integrations: [Sentry.mobileReplayIntegration(), Sentry.feedbackIntegration()]

//     // uncomment the line below to enable Spotlight (https://spotlightjs.com)
//     // spotlight: __DEV__,
// });

export {
    // Catch any errors thrown by the Layout component.
    ErrorBoundary
} from 'expo-router';

export const unstable_settings = {
    // Ensure that reloading on `/modal` keeps a back button present.
    initialRouteName: '(tabs)'
};

// Prevent the splash screen from auto-hiding before asset loading is complete.
SplashScreen.preventAutoHideAsync();

// Check app integrity on app start
if (Platform.OS === 'android') {
    (async () => {
        try {
            await Integrity.prepareIntegrityTokenProviderAsync(
                process.env['EXPO_PUBLIC_GOOGLE_PROJECT_ID'] ?? '0'
            );
            console.log('Android app integrity provider initialised.');
        } catch (error) {
            console.warn('App integrity not available on this device:', error);
        }
    })();
} else if (Platform.OS === 'ios') {
    if (Integrity.isSupported) {
        console.log('iOS App Attest is supported on this device.');
    }
}

// export default Sentry.wrap(function RootLayout() {
export default function RootLayout() {
    useExpoPushToken();
    useDeviceUuid();
    const [loaded, error] = useFonts({
        Inter: require('@/assets/fonts/InterVariable.ttf'),
        ...FontAwesome.font
    });

    const isOnboarded = useAuthStore((s) => s.isOnboarded);
    const [storesReady, setStoresReady] = useState(false);
    const [showSplashAnim, setShowSplashAnim] = useState(true);

    // Hydrate persisted stores on app launch
    useEffect(() => {
        Promise.all([
            useAuthStore.getState().hydrate(),
            useProfileStore.getState().hydrate(),
            useConsentStore.getState().hydrate(),
            useTrustedAppsStore.getState().hydrate(),
            useSettingsStore.getState().hydrate(),
            useSessionsStore.getState().hydrate()
        ]).then(() => setStoresReady(true));

        // Run security checks in the background
        checkDeviceSecurity().then((status) => {
            if (status.warnings.length > 0) {
                console.warn('Security warnings:', status.warnings);
            }
        });
    }, []);

    // Expo Router uses Error Boundaries to catch errors in the navigation tree.
    useEffect(() => {
        if (error) throw error;
    }, [error]);

    const onSplashComplete = useCallback(() => {
        setShowSplashAnim(false);
    }, []);

    if (!loaded || !storesReady) {
        return null;
    }

    return (
        <>
            <RootLayoutNav isOnboarded={isOnboarded} />
            {showSplashAnim && (
                <SplashAnimation
                    onComplete={onSplashComplete}
                    onReady={() => SplashScreen.hideAsync()}
                />
            )}
        </>
    );
}

function KeepAwake() {
    useKeepAwake();
    return null;
}

function RootLayoutNav({ isOnboarded }: { isOnboarded: boolean }) {
    const colorScheme = useColorScheme();
    const router = useRouter();

    useEffect(() => {
        if (!isOnboarded) {
            router.replace('/onboarding');
        }
    }, [isOnboarded]);

    return (
        <>
            {__DEV__ && <KeepAwake />}
            <ThemeProvider value={colorScheme === 'dark' ? DarkTheme : DefaultTheme}>
                <Stack screenOptions={{ headerShown: false }} />
            </ThemeProvider>
        </>
    );
}
